import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DATA_PATH = PROJECT_ROOT / "tests" / "data" / "yandex_expected.json"


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def share_link() -> str:
    return "https://disk.yandex.com/d/mzD4nTKBCi2ARw"


@pytest.fixture(scope="session")
def expected_data() -> dict:
    with DATA_PATH.open() as f:
        return json.load(f)


@pytest.fixture(scope="session")
def expected_tree(expected_data: dict) -> dict:
    return expected_data["expected_tree"]


@pytest.fixture(scope="session")
def expected_subfolder_flat(expected_data: dict) -> dict:
    return expected_data["expected_subfolder_flat"]
