#!/usr/bin/env python3
import argparse, hashlib, os, re, sys, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter, Retry
from tqdm import tqdm

LIST_URL = "https://cloud-api.yandex.net/v1/disk/public/resources"
DL_URL   = "https://cloud-api.yandex.net/v1/disk/public/resources/download"

def extract_token(link: str) -> str:
    m = re.search(r"/d/([A-Za-z0-9_-]+)", link)
    if not m:
        raise ValueError(f"Could not extract token from link: {link}")
    return m.group(1)

def normalize_public_key(link: str) -> str:
    token = extract_token(link)
    return f"https://disk.yandex.com/d/{token}"

def part_path(path: Path) -> Path:
    return path.parent / (path.name + ".part")

def make_session(max_workers: int) -> requests.Session:
    s = requests.Session()
    retries = Retry(total=8, backoff_factor=0.6,
                    status_forcelist=(429,500,502,503,504),
                    allowed_methods=frozenset(["GET"]),
                    raise_on_status=False)
    s.mount("https://", HTTPAdapter(max_retries=retries,
                                    pool_connections=max_workers,
                                    pool_maxsize=max_workers))
    return s

def api_list(session: requests.Session, public_key: str, path: str, limit: int = 1000):
    offset = 0
    while True:
        r = session.get(LIST_URL, params={
            "public_key": public_key, "path": path,
            "limit": limit, "offset": offset
        }, timeout=(20, 60))
        r.raise_for_status()
        data = r.json()
        embedded = data.get("_embedded", {})
        items = embedded.get("items", [])
        total = embedded.get("total", len(items))
        for it in items:
            yield it
        offset += len(items)
        if offset >= total or not items:
            break

def api_download_href(session: requests.Session, public_key: str, item_path: str) -> str:
    r = session.get(DL_URL, params={"public_key": public_key, "path": item_path}, timeout=(20,60))
    r.raise_for_status()
    href = r.json().get("href")
    if not href:
        raise RuntimeError(f"No download href for {item_path}")
    return href

def crawl_recursive(session, public_key, root_path, rel: Path, preserve_root: bool):
    """
    rel: local base path component(s) under dest_root
    preserve_root: if False, do not include the first folder name (flatten the top level)
    """
    files = []
    for it in api_list(session, public_key, root_path):
        typ = it.get("type"); name = it.get("name"); item_path = it.get("path")
        if typ == "dir":
            child_rel = rel / name if preserve_root or rel != Path(".") else Path(name) if preserve_root else Path(name)
            # If not preserving root and current rel == ".", we still need to include subfolder names beneath root_path
            next_rel = (rel / name) if preserve_root or rel != Path(".") else Path(name)
            files.extend(crawl_recursive(session, public_key, item_path, next_rel, True))  # after the first hop, always preserve structure
        elif typ == "file":
            files.append({
                "item_path": item_path,
                "relpath": rel / name,
                "size": int(it.get("size", 0)),
                "md5": it.get("md5"),
                "sha256": it.get("sha256"),
            })
    return files

def hash_file(path: Path, algo: str, pbar: tqdm | None = None, chunk=1<<20) -> str:
    h = hashlib.sha256() if algo == "sha256" else hashlib.md5()
    with path.open("rb", buffering=0) as f:
        for chunk_bytes in iter(lambda: f.read(chunk), b""):
            h.update(chunk_bytes)
            if pbar is not None:
                pbar.update(len(chunk_bytes))
    return h.hexdigest()

def verify_file(path: Path, sha256: str | None, md5: str | None, pbar: tqdm | None = None):
    if sha256:
        if hash_file(path, "sha256", pbar) != sha256:
            raise ValueError(f"SHA-256 mismatch: {path}")
    elif md5:
        if hash_file(path, "md5", pbar) != md5:
            raise ValueError(f"MD5 mismatch: {path}")

def download_one(session, public_key, dest_root: Path, rec: dict, pbar: tqdm, do_verify: bool):
    dest = dest_root / rec["relpath"]
    tmp  = part_path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    expected_size = rec["size"]
    sha256 = rec.get("sha256"); md5 = rec.get("md5")

    # fast-skip if complete (and valid if verify is on)
    if dest.exists() and (expected_size == 0 or dest.stat().st_size == expected_size):
        if do_verify and (sha256 or md5):
            verify_file(dest, sha256, md5, pbar=None)
        return

    resume_at = tmp.stat().st_size if tmp.exists() else 0
    if expected_size and resume_at > expected_size:
        tmp.unlink(missing_ok=True); resume_at = 0

    attempts = 0
    while True:
        attempts += 1
        href = api_download_href(session, public_key, rec["item_path"])
        headers = {"Range": f"bytes={resume_at}-"} if resume_at > 0 else {}
        try:
            with session.get(href, headers=headers, stream=True, timeout=(20,60)) as r:
                if r.status_code in (401,403):
                    if attempts < 6:
                        time.sleep(1.5*attempts); continue
                    r.raise_for_status()
                if r.status_code not in (200,206):
                    if r.status_code == 200 and resume_at > 0:
                        tmp.unlink(missing_ok=True); resume_at = 0
                    else:
                        r.raise_for_status()
                mode = "ab" if resume_at > 0 else "wb"
                with tmp.open(mode) as f:
                    for chunk_bytes in r.iter_content(1<<20):
                        if not chunk_bytes: continue
                        f.write(chunk_bytes); pbar.update(len(chunk_bytes))
            break
        except Exception:
            if attempts >= 6: raise
            time.sleep(min(10, 1.5*attempts))

    if expected_size and tmp.stat().st_size != expected_size:
        raise RuntimeError(f"Size mismatch: {dest} got {tmp.stat().st_size} expected {expected_size}")

    if do_verify and (sha256 or md5):
        verify_file(tmp, sha256, md5, pbar=None)

    tmp.rename(dest)

def verify_only(dest_root: Path, files: list[dict], workers: int) -> int:
    total_to_hash, work, missing = 0, [], []
    for rec in files:
        p = dest_root / rec["relpath"]
        if p.exists() and p.is_file():
            total_to_hash += rec.get("size", 0) or 0
            work.append((p, rec.get("sha256"), rec.get("md5")))
        else:
            missing.append(str(rec["relpath"]))

    if missing:
        print(f"[verify] missing files: {len(missing)}", file=sys.stderr)

    errors = []
    def task(entry, pbar: tqdm):
        path, sha256, md5 = entry
        try:
            verify_file(path, sha256, md5, pbar=pbar)
            return (path, True, "")
        except Exception as e:
            return (path, False, str(e))

    with tqdm(total=total_to_hash, unit="B", unit_scale=True, unit_divisor=1024, desc="Verifying") as pbar:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(task, e, pbar) for e in work]
            for fut in as_completed(futures):
                path, ok, msg = fut.result()
                if not ok: errors.append((str(path), msg))

    print(f"[verify] checked: {len(work)} files | missing: {len(missing)} | failed: {len(errors)}", file=sys.stderr)
    if missing:
        for m in missing[:10]: print(f"[verify] missing: {m}", file=sys.stderr)
        if len(missing) > 10: print(f"[verify] ... and {len(missing)-10} more missing", file=sys.stderr)
    if errors:
        for p, msg in errors[:10]: print(f"[verify] FAIL: {p} :: {msg}", file=sys.stderr)
        if len(errors) > 10: print(f"[verify] ... and {len(errors)-10} more failures", file=sys.stderr)
    return 0 if not errors and not missing else 2

def list_top_level(session, public_key):
    return list(api_list(session, public_key, "/"))

def main():
    ap = argparse.ArgumentParser(description="Parallel, resumable, hash-verified downloader for Yandex Disk public shares.")
    ap.add_argument("-l","--link", required=True, help="Public Yandex Disk link (https://disk.yandex.com/d/<token>)")
    ap.add_argument("-d","--dest", default=None, help="Destination parent directory. Default = token.")
    ap.add_argument("-f","--folder", default=None, help="Subfolder path inside the share (e.g. '100SRGB2'). If omitted, use root '/'.")
    ap.add_argument("--all-top-level", action="store_true", help="Enumerate '/' and download every first-level entry.")
    ap.add_argument("--no-preserve-root", action="store_true", help="Do NOT include the requested folder name as a local top-level dir.")
    ap.add_argument("-w","--workers", type=int, default=16, help="Parallel threads (default 16).")
    ap.add_argument("--no-verify", action="store_true", help="Skip per-file hash verification during download.")
    ap.add_argument("--verify-only", action="store_true", help="Do not download; verify hashes of existing files.")
    args = ap.parse_args()

    token = extract_token(args.link)
    public_key = normalize_public_key(args.link)
    dest_parent = Path(args.dest if args.dest else token)
    dest_parent.mkdir(parents=True, exist_ok=True)

    session = make_session(args.workers)

    # Build list of “targets” (each is (remote_path, local_rel_base))
    targets = []
    if args.all_top_level:
        # enumerate root and add each entry as a target
        print(f"[list] link={public_key} path='/' → dest='{dest_parent}' (all top-level)", file=sys.stderr)
        for it in api_list(session, public_key, "/"):
            name = it.get("name"); typ = it.get("type"); path = it.get("path")
            if typ == "dir":
                # local base dir for this target is either 'name/' or '.' if flattening
                local_rel = Path(name) if not args.no_preserve_root else Path(".")
                targets.append( (path, local_rel, not args.no_preserve_root) )
            elif typ == "file":
                # a file at root: rel is '.' unless preserving root as a dummy container
                targets.append( (path, Path("."), True) )
    else:
        root_path = f"/{args.folder.strip('/')}" if args.folder else "/"
        # If folder provided and preserve-root enabled, include it as top-level in local tree.
        local_rel = Path(root_path.strip("/")) if (root_path != "/" and not args.no_preserve_root) else Path(".")
        print(f"[list] link={public_key} path='{root_path}' → dest='{dest_parent}'", file=sys.stderr)
        targets.append( (root_path, local_rel, not args.no_preserve_root) )

    # Crawl all targets and merge file lists
    files = []
    for remote_path, local_rel, preserve_root in targets:
        files.extend(crawl_recursive(session, public_key, remote_path, rel=local_rel, preserve_root=preserve_root))

    if not files:
        print("No files found.", file=sys.stderr); return 1

    # Modes
    if args.verify_only:
        return verify_only(dest_parent, files, args.workers)

    total_bytes = sum(f.get("size",0) for f in files)
    print(f"[list] files={len(files)} total={total_bytes/1e9:.2f} GB", file=sys.stderr)

    already = 0
    for rec in files:
        dest = dest_parent / rec["relpath"]
        if dest.exists():
            if rec["size"] and dest.stat().st_size == rec["size"]:
                already += rec["size"]
            else:
                part = part_path(dest)
                if part.exists(): already += part.stat().st_size

    with tqdm(total=total_bytes, unit="B", unit_scale=True, unit_divisor=1024,
              desc="Downloading", initial=already) as pbar:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(download_one, session, public_key, dest_parent, rec, pbar, not args.no_verify)
                    for rec in files]
            for fut in as_completed(futs): fut.result()

    print("Done.", file=sys.stderr); return 0

if __name__ == "__main__":
    sys.exit(main())
