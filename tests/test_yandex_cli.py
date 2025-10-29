from pathlib import Path

import pytest
import requests

import YandexCLI


def as_key(relpath) -> str:
    return str(relpath).replace("\\", "/")


@pytest.fixture(scope="module")
def public_key(share_link: str) -> str:
    return YandexCLI.normalize_public_key(share_link)


@pytest.fixture(scope="module")
def yandex_session():
    session = YandexCLI.make_session(max_workers=2)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="module")
def root_listing(yandex_session, public_key):
    try:
        return YandexCLI.crawl_recursive(
            yandex_session, public_key, "/", rel=Path("."), preserve_root=True
        )
    except requests.RequestException as exc:
        pytest.skip(f"Yandex Disk API unavailable: {exc}")


def test_extract_token_and_normalize(share_link: str):
    token = YandexCLI.extract_token(share_link)
    assert token == "mzD4nTKBCi2ARw"
    assert YandexCLI.normalize_public_key(share_link) == share_link


def test_crawl_recursive_root_structure(root_listing, expected_tree):
    actual = {as_key(rec["relpath"]): rec for rec in root_listing}
    assert set(actual.keys()) == set(expected_tree.keys())

    for rel, expected in expected_tree.items():
        rec = actual[rel]
        assert rec["size"] == expected["size"]
        assert rec["md5"] == expected["md5"]
        assert rec["sha256"] == expected["sha256"]


def test_crawl_subfolder_without_preserving_root(
    yandex_session, public_key, expected_subfolder_flat
):
    try:
        results = YandexCLI.crawl_recursive(
            yandex_session, public_key, "/subfolder", rel=Path("."), preserve_root=False
        )
    except requests.RequestException as exc:
        pytest.skip(f"Yandex Disk API unavailable: {exc}")

    actual = {as_key(rec["relpath"]): rec for rec in results}
    assert set(actual.keys()) == set(expected_subfolder_flat.keys())

    for rel, expected in expected_subfolder_flat.items():
        rec = actual[rel]
        assert rec["size"] == expected["size"]
        assert rec["md5"] == expected["md5"]
        assert rec["sha256"] == expected["sha256"]
