import hashlib
import subprocess
import sys
from pathlib import Path

import pytest


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run_cli(project_root: Path, *args: str):
    cmd = [sys.executable, "YandexCLI.py", *args]
    subprocess.run(cmd, cwd=project_root, check=True)


@pytest.mark.network
def test_download_and_verify_subfolder_e2e(
    tmp_path: Path, project_root: Path, share_link: str, expected_subfolder_flat: dict
):
    dest = tmp_path / "downloads"
    dest.mkdir()

    # Download just the subfolder contents, flattening the root directory locally.
    run_cli(
        project_root,
        "-l",
        share_link,
        "-f",
        "subfolder",
        "--no-preserve-root",
        "-d",
        str(dest),
    )

    for filename, meta in expected_subfolder_flat.items():
        local_path = dest / filename
        assert local_path.exists(), f"Missing file {filename}"
        assert local_path.stat().st_size == meta["size"]
        assert compute_sha256(local_path) == meta["sha256"]

    # Re-run in verify-only mode to exercise the verification path.
    run_cli(
        project_root,
        "-l",
        share_link,
        "-f",
        "subfolder",
        "--no-preserve-root",
        "-d",
        str(dest),
        "--verify-only",
    )
