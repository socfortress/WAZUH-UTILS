"""WAZUH-UTILS routes: authentication, path safety, allow-list, hashes, atomic writes.

Run with: pip install -r requirements.in -r requirements-dev.in && python -m pytest
"""
import hashlib
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app  # noqa: E402

KEY = "test-key-0123456789"
WATCHDOG = b"# watchdog\r\nWrite-Output 'ok'\r\n"
RELOAD = b"\xef\xbb\xbf# reload\n"
SYSMON = b'<Sysmon schemaversion="4.60"><EventFiltering/></Sysmon>'


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def shared(tmp_path, monkeypatch):
    (tmp_path / "Windows_acme").mkdir()
    (tmp_path / "Linux_acme").mkdir()
    monkeypatch.setenv("WAZUH_UTILS_SHARED_DIR", str(tmp_path))
    for name in (
        "WAZUH_UTILS_API_KEY",
        "WAZUH_UTILS_API_KEY_FILE",
        "WAZUH_UTILS_ALLOWED_SHA256",
    ):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


@pytest.fixture
def client():
    return TestClient(app)


def post_scripts(client, group="Windows_acme", files=None, hashes=None, key=KEY):
    files = (
        files
        if files is not None
        else [("sysmon_watchdog.ps1", WATCHDOG), ("sysmon_config_reload.ps1", RELOAD)]
    )
    hashes = hashes if hashes is not None else [sha(d) for _, d in files]
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return client.post(
        "/provision_worker/shared-files",
        data={"group": group, "sha256": hashes},
        files=[
            ("files", (name, data, "application/octet-stream")) for name, data in files
        ],
        headers=headers,
    )


# ---------------------------------------------------------------- /shared-files


def test_shared_files_is_disabled_without_a_configured_key(shared, client):
    response = post_scripts(client)
    assert response.status_code == 503
    assert not (shared / "Windows_acme" / "sysmon_watchdog.ps1").exists()


def test_shared_files_rejects_a_wrong_or_missing_key(shared, client, monkeypatch):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    assert post_scripts(client, key="wrong").status_code == 401
    assert post_scripts(client, key=None).status_code == 401


def test_shared_files_writes_exact_bytes_atomically(shared, client, monkeypatch):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    response = post_scripts(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] and {w["name"] for w in body["written"]} == {
        "sysmon_watchdog.ps1",
        "sysmon_config_reload.ps1",
    }
    assert (shared / "Windows_acme" / "sysmon_watchdog.ps1").read_bytes() == WATCHDOG
    assert (
        shared / "Windows_acme" / "sysmon_config_reload.ps1"
    ).read_bytes() == RELOAD  # BOM kept
    assert (
        oct((shared / "Windows_acme" / "sysmon_watchdog.ps1").stat().st_mode & 0o777)
        == "0o660"
    )
    assert not [
        p for p in (shared / "Windows_acme").iterdir() if p.name.startswith(".")
    ]  # no temp files left


def test_key_file_works_and_an_unreadable_key_file_fails_closed(
    shared,
    client,
    monkeypatch,
    tmp_path,
):
    key_file = tmp_path / "key"
    key_file.write_text(KEY + "\n")
    monkeypatch.setenv("WAZUH_UTILS_API_KEY_FILE", str(key_file))
    assert post_scripts(client).status_code == 200
    monkeypatch.setenv("WAZUH_UTILS_API_KEY_FILE", str(tmp_path / "missing"))
    assert post_scripts(client).status_code == 503
    # ... and the legacy route does not silently open up either.
    response = client.post(
        "/provision_worker/sysmon-config",
        data={"customer_code": "acme"},
        files={"sysmon_config": ("sysmon_config.xml", SYSMON, "application/xml")},
    )
    assert response.status_code == 503


@pytest.mark.parametrize(
    "group",
    [
        "Windows_../../etc",
        "../Windows_acme",
        "Windows_acme/..",
        "Linux_acme",
        "Windows_missing",
        "Windows_a b",
    ],
)
def test_shared_files_refuses_bad_or_unknown_groups(shared, client, monkeypatch, group):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    response = post_scripts(client, group=group)
    assert response.status_code in (400, 404)
    assert not (shared / "Windows_missing").exists()


def test_shared_files_refuses_names_outside_the_allow_list(shared, client, monkeypatch):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    for name in (
        "agent.conf",
        "evil.ps1",
        "../sysmon_watchdog.ps1",
        "sysmon_config.xml",
    ):
        response = post_scripts(client, files=[(name, WATCHDOG)])
        assert response.status_code == 400, name
    assert sorted(p.name for p in (shared / "Windows_acme").iterdir()) == []


def test_shared_files_checks_every_hash_before_writing_anything(
    shared,
    client,
    monkeypatch,
):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    response = post_scripts(client, hashes=[sha(WATCHDOG), sha(b"something else")])
    assert response.status_code == 400
    assert list((shared / "Windows_acme").iterdir()) == []
    assert (
        post_scripts(client, hashes=[sha(WATCHDOG)]).status_code == 400
    )  # count mismatch


def test_pinned_hash_allow_list(shared, client, monkeypatch):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    monkeypatch.setenv("WAZUH_UTILS_ALLOWED_SHA256", f"{sha(WATCHDOG)}, {sha(RELOAD)}")
    assert post_scripts(client).status_code == 200
    other = b"# a different, unpinned watchdog\n"
    response = post_scripts(client, files=[("sysmon_watchdog.ps1", other)])
    assert response.status_code == 403
    assert (shared / "Windows_acme" / "sysmon_watchdog.ps1").read_bytes() == WATCHDOG


def test_duplicate_and_oversized_files_are_refused(shared, client, monkeypatch):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    dup = [("sysmon_watchdog.ps1", WATCHDOG), ("sysmon_watchdog.ps1", WATCHDOG)]
    assert post_scripts(client, files=dup).status_code == 400
    big = b"x" * (1024 * 1024 + 1)
    assert post_scripts(client, files=[("sysmon_watchdog.ps1", big)]).status_code == 413


def test_a_symlink_at_the_target_is_replaced_not_followed(
    shared,
    client,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"do not touch")
    os.symlink(victim, shared / "Windows_acme" / "sysmon_watchdog.ps1")
    assert (
        post_scripts(client, files=[("sysmon_watchdog.ps1", WATCHDOG)]).status_code
        == 200
    )
    assert victim.read_bytes() == b"do not touch"
    assert not (shared / "Windows_acme" / "sysmon_watchdog.ps1").is_symlink()


# ---------------------------------------------------------------- /sysmon-config


def post_sysmon(
    client,
    customer_code="acme",
    data=SYSMON,
    name="sysmon_config.xml",
    key=None,
):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return client.post(
        "/provision_worker/sysmon-config",
        data={"customer_code": customer_code},
        files={"sysmon_config": (name, data, "application/xml")},
        headers=headers,
    )


def test_sysmon_config_stays_open_without_a_key_for_backwards_compatibility(
    shared,
    client,
):
    response = post_sysmon(client)
    assert response.status_code == 200, response.text
    assert (shared / "Windows_acme" / "sysmon_config.xml").read_bytes() == SYSMON


def test_sysmon_config_requires_the_key_once_configured(shared, client, monkeypatch):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    assert post_sysmon(client).status_code == 401
    assert post_sysmon(client, key=KEY).status_code == 200


@pytest.mark.parametrize(
    "customer_code",
    ["../../../tmp/x", "acme/../../x", "missing", "a/b"],
)
def test_sysmon_config_refuses_path_tricks_and_unknown_groups(
    shared,
    client,
    customer_code,
):
    assert post_sysmon(client, customer_code=customer_code).status_code in (400, 404)
    assert not list(shared.parent.glob("**/x/sysmon_config.xml"))


def test_sysmon_config_must_be_a_sysmon_xml_document(shared, client):
    assert post_sysmon(client, data=b"not xml").status_code == 400
    assert post_sysmon(client, data=b"<ossec_config/>").status_code == 400
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa">'
        b'<!ENTITY b "&a;&a;">]><Sysmon>&b;</Sysmon>'
    )
    assert (
        post_sysmon(client, data=bomb).status_code == 400
    )  # entities refused (defusedxml)
    assert post_sysmon(client, name="sysmon_config.txt").status_code == 400
    assert not (shared / "Windows_acme" / "sysmon_config.xml").exists()


def test_spaces_in_the_customer_code_still_map_to_underscores(shared, client):
    (shared / "Windows_big_co").mkdir()
    assert post_sysmon(client, customer_code="big co").status_code == 200
    assert (shared / "Windows_big_co" / "sysmon_config.xml").exists()


def test_no_cors_headers_are_sent(shared, client):
    response = client.options(
        "/provision_worker/shared-files",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in response.headers}


# ---------------------------------------------------------------- hardening


def test_unauthenticated_uploads_are_refused_before_the_body_is_parsed(
    shared,
    client,
    monkeypatch,
):
    import app.routes.utils as routes

    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)

    def must_not_run(*args, **kwargs):
        raise AssertionError("the route ran for an unauthenticated request")

    monkeypatch.setattr(routes, "group_dir", must_not_run)
    response = post_scripts(client, key="wrong")
    assert response.status_code == 401
    assert response.json() == {
        "success": False,
        "message": "Invalid or missing API key",
    }
    response = post_sysmon(client)
    assert response.status_code == 401


def test_oversized_bodies_are_refused_from_the_headers(shared, client, monkeypatch):
    from app import middleware

    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    monkeypatch.setattr(middleware, "MAX_BODY_BYTES", 100)
    assert post_scripts(client).status_code == 413


def test_a_group_symlinked_outside_the_shared_dir_is_refused(
    shared,
    client,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    os.symlink(outside, shared / "Windows_evil")
    assert post_scripts(client, group="Windows_evil").status_code == 400
    assert list(outside.iterdir()) == []


def test_a_failed_write_leaves_no_temp_files_and_the_old_pair_intact(
    shared,
    client,
    monkeypatch,
):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    assert post_scripts(client).status_code == 200
    calls = {"n": 0}
    real_replace = os.replace

    def flaky_replace(*args, **kwargs):
        calls["n"] += 1
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", flaky_replace)
    new = [
        ("sysmon_watchdog.ps1", b"# new watchdog\n"),
        ("sysmon_config_reload.ps1", b"# new reload\n"),
    ]
    response = post_scripts(TestClient(app, raise_server_exceptions=False), files=new)
    monkeypatch.setattr(os, "replace", real_replace)
    assert response.status_code == 500
    assert response.json() == {"success": False, "message": "Internal error"}
    folder = shared / "Windows_acme"
    assert (folder / "sysmon_watchdog.ps1").read_bytes() == WATCHDOG
    assert (folder / "sysmon_config_reload.ps1").read_bytes() == RELOAD
    assert not [p for p in folder.iterdir() if p.name.startswith(".")]


def test_files_are_handed_to_wazuh_through_the_file_descriptor_when_root(
    shared,
    client,
    monkeypatch,
):
    from app import files

    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    owners = []
    monkeypatch.setattr(files, "_wazuh_ids", lambda: (4242, 4243))
    monkeypatch.setattr(files.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        files.os,
        "fchown",
        lambda fd, uid, gid: owners.append((uid, gid)),
    )
    monkeypatch.setattr(
        files.os,
        "chown",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("path chown")),
    )
    assert post_scripts(client).status_code == 200
    assert owners == [(4242, 4243), (4242, 4243)]


def test_name_bound_pins_cannot_be_swapped_between_the_two_scripts(
    shared,
    client,
    monkeypatch,
):
    monkeypatch.setenv("WAZUH_UTILS_API_KEY", KEY)
    monkeypatch.setenv(
        "WAZUH_UTILS_ALLOWED_SHA256",
        "sysmon_watchdog.ps1:%s,sysmon_config_reload.ps1:%s"
        % (sha(WATCHDOG), sha(RELOAD)),
    )
    assert post_scripts(client).status_code == 200
    swapped = [("sysmon_watchdog.ps1", RELOAD)]
    assert post_scripts(client, files=swapped).status_code == 403


def test_interactive_docs_are_not_served(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
