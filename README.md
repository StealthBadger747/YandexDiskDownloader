# YandexDisk Downloader and Verifier

Parallel, resumable downloader for public Yandex Disk shares. Recursively walks folders, verifies each file (SHA-256/MD5), and bypasses the web “Download as ZIP” limit by fetching files directly via the public API.

## Features

- 🚀 Parallel, multithreaded downloads (configurable; default 16)
- 🔄 Resume via HTTP Range and `.part` files
- 🔐 Per-file hash verification (SHA-256 preferred, MD5 fallback)
- 🗂️ Recursive folder traversal
- 🧪 “Verify later” mode (`--verify-only`) without re-downloading
- 📦 Bypasses the web “Download as ZIP” restriction (no desktop client needed)
- 🔓 No login required (public shares only)

### Comparison with Other Yandex Disk Tools

| Tool | Recursive | Parallel | Hash verify | Resumable | Preserves tree | **Avoids web ZIP** | CLI |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **[This tool (YandexCLI.py)](YandexCLI.py)** | ✅ | ✅ | ✅ (SHA-256/MD5) | ✅ | ✅ | ✅ | ✅ |
| **[ruarxive/ydiskarc](https://github.com/ruarxive/ydiskarc)** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ / ❌ | ✅ |
| **[redmanmale/ya-disk-downloader](https://github.com/redmanmale/ya-disk-downloader)** | ❌ | ❌ | ❌ | ❓ | — | ❓ | ✅ |
| **[wldhx/yadisk-direct](https://github.com/wldhx/yadisk-direct)** | ❌ | ❌ | ❌ | ❌ | — | — | ✅ |
| **[SecFathy/YandexDown](https://github.com/SecFathy/YandexDown)** | ❌ | ❌ | ❌ | ❓ | — | ❌ | ✅ |

**Legend:** ✅ = supported, ❌ = not supported, ❓ = unclear, — = not applicable.

Notes:  
- `ydiskarc` has two modes: `sync` downloads files recursively (avoids ZIP), while `full` downloads Yandex’s pre-zipped archive.  
- `ya-disk-downloader` downloads files from a flat folder only (no recursion).  
- `yadisk-direct` and `YandexDown` handle single-file links, not folders.

## Installation

**Normal installation:**
```bash
pip install requests tqdm
```

**If you have Nix:** *(optional)*
```bash
nix shell --impure --expr 'let pkgs = import <nixpkgs> {}; in pkgs.python312.withPackages (ps: [ ps.requests ps.tqdm ])'
```

## Usage

### Download a specific folder

```bash
python3 YandexCLI.py \
  -l 'https://disk.yandex.com/d/EXAMPLE_TOKEN' \
  -f 'FolderName'
# Creates ./EXAMPLE_TOKEN/FolderName/... locally
```

### Download all top-level folders

```bash
python3 YandexCLI.py \
  -l 'https://disk.yandex.com/d/EXAMPLE_TOKEN' \
  --all-top-level
# Creates ./EXAMPLE_TOKEN/<TopLevel1>/..., ./EXAMPLE_TOKEN/<TopLevel2>/...
```

### Skip verification for speed, then verify later

```bash
python3 YandexCLI.py -l 'https://disk.yandex.com/d/EXAMPLE_TOKEN' -f 'FolderName' --no-verify
python3 YandexCLI.py -l 'https://disk.yandex.com/d/EXAMPLE_TOKEN' -f 'FolderName' --verify-only
```

### Flatten the layout (omit the root folder name locally)

```bash
python3 YandexCLI.py \
  -l 'https://disk.yandex.com/d/EXAMPLE_TOKEN' \
  -f 'FolderName' \
  --no-preserve-root
```

**Common flags**

- `-w/--workers N` — number of download threads (default: 16)
- `-d/--dest DIR` — destination parent directory (default: token extracted from the link)

## Verification behavior

Each file (per thread) is downloaded, size-checked, hash-verified, and renamed from `.part` only after the hash passes. You can re-run integrity checks at any time with `--verify-only` (no downloads).

## Notes

- Uses Yandex’s public API only; no credentials required.
- Supports only public shares; authenticated/private disks are out of scope.
- Retries on 429/5xx are built in.
- Safe to interrupt; verified files are not re-downloaded or overwritten.

## License

MIT
