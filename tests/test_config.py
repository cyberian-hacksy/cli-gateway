"""Configuration loading: strict about secrets, and never repeats them in errors."""
import base64
import json
import os
import stat

import pytest

from cgw import config

PSK = bytes(range(32))
PSK_TEXT = base64.urlsafe_b64encode(PSK).rstrip(b"=").decode()
OTHER_PSK = bytes(range(1, 33))
OTHER_PSK_TEXT = base64.urlsafe_b64encode(OTHER_PSK).rstrip(b"=").decode()
INTERNAL_KEY = "internal-key-0123456789abcdef0123456789"
LOCAL_KEY = "local-bearer-key-0123456789abcdef"
REMOTE_ENV = {"CGW_CLIENT_POC_1": PSK_TEXT, "CGW_CLIPROXY_KEY": INTERNAL_KEY}
LOCAL_FILE = {"remote_url": "https://gateway.example.com", "kid": "poc-1", "psk": PSK_TEXT, "local_key": LOCAL_KEY}


def write_local(tmp_path, content=None, mode=0o600):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(LOCAL_FILE if content is None else content))
    os.chmod(path, mode)
    return path


# --- remote: environment variables -----------------------------------------------------

def test_remote_settings_are_built_from_the_environment():
    loaded = config.load_remote(REMOTE_ENV)
    assert loaded.settings.keys == {"poc-1": PSK}
    assert loaded.settings.upstream_key == INTERNAL_KEY
    assert loaded.settings.upstream_url == "http://127.0.0.1:8317"
    assert loaded.port == 8080


def test_remote_port_and_upstream_can_be_overridden():
    loaded = config.load_remote({**REMOTE_ENV, "PORT": "9000", "CGW_UPSTREAM_URL": "http://127.0.0.1:9999"})
    assert loaded.port == 9000
    assert not hasattr(loaded, "ledger_path")
    assert loaded.settings.upstream_url == "http://127.0.0.1:9999"


@pytest.mark.parametrize("missing", ["CGW_CLIPROXY_KEY"])
def test_missing_remote_variable_is_named_in_the_error(missing):
    env = {name: value for name, value in REMOTE_ENV.items() if name != missing}
    with pytest.raises(config.ConfigError, match=missing):
        config.load_remote(env)


# --- remote: one variable per client ---------------------------------------------------

def test_every_client_variable_becomes_a_key_named_after_it():
    loaded = config.load_remote({**REMOTE_ENV, "CGW_CLIENT_WORK_LAPTOP": OTHER_PSK_TEXT})
    assert loaded.settings.keys == {"poc-1": PSK, "work-laptop": OTHER_PSK}


def test_a_gateway_with_no_client_refuses_to_start():
    with pytest.raises(config.ConfigError, match="CGW_CLIENT_"):
        config.load_remote({"CGW_CLIPROXY_KEY": INTERNAL_KEY})


def test_the_old_single_key_variables_do_not_admit_anyone():
    # They are ignored, never trusted: a gateway that has only them has no client.
    with pytest.raises(config.ConfigError, match="CGW_CLIENT_"):
        config.load_remote({"CGW_KID": "poc-1", "CGW_PSK": PSK_TEXT, "CGW_CLIPROXY_KEY": INTERNAL_KEY})
    loaded = config.load_remote({**REMOTE_ENV, "CGW_KID": "old", "CGW_PSK": OTHER_PSK_TEXT})
    assert loaded.settings.keys == {"poc-1": PSK}


@pytest.mark.parametrize("variable", ["CGW_CLIENT_", "CGW_CLIENT_laptop", "CGW_CLIENT_A__B", "CGW_CLIENT__A",
                                      "CGW_CLIENT_A_", "CGW_CLIENT_A-B", "CGW_CLIENT_" + "A" * 41])
def test_a_badly_named_client_variable_is_refused_by_name(variable):
    with pytest.raises(config.ConfigError, match=variable):
        config.load_remote({**REMOTE_ENV, variable: OTHER_PSK_TEXT})


@pytest.mark.parametrize("psk", ["", "short", PSK_TEXT + "=", PSK_TEXT[:-1], "!" * 43, PSK_TEXT + "AAAA"])
def test_client_key_that_is_not_32_bytes_of_canonical_base64url_is_refused(psk):
    with pytest.raises(config.ConfigError, match="CGW_CLIENT_POC_1"):
        config.load_remote({**REMOTE_ENV, "CGW_CLIENT_POC_1": psk})


def test_all_zero_client_key_is_refused():
    zero = base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode()
    with pytest.raises(config.ConfigError, match="CGW_CLIENT_POC_1"):
        config.load_remote({**REMOTE_ENV, "CGW_CLIENT_POC_1": zero})


def test_two_clients_may_not_share_a_key():
    # Otherwise removing one would not shut out whoever holds the key.
    with pytest.raises(config.ConfigError, match="CGW_CLIENT_COPY.*CGW_CLIENT_POC_1|CGW_CLIENT_POC_1.*CGW_CLIENT_COPY"):
        config.load_remote({**REMOTE_ENV, "CGW_CLIENT_COPY": PSK_TEXT})


@pytest.mark.parametrize("name,value", [
    ("CGW_CLIPROXY_KEY", "short"), ("PORT", "not-a-port"), ("PORT", "70000"),
    ("CGW_UPSTREAM_URL", "https://api.example.com"), ("CGW_UPSTREAM_URL", "http://10.0.0.5:8317"),
])
def test_invalid_remote_value_is_refused(name, value):
    with pytest.raises(config.ConfigError, match=name):
        config.load_remote({**REMOTE_ENV, name: value})


def test_remote_errors_never_contain_secret_values():
    for name in ("CGW_CLIENT_POC_1", "CGW_CLIPROXY_KEY"):
        secret = "SECRET-VALUE-do-not-print-" + name
        with pytest.raises(config.ConfigError) as caught:
            config.load_remote({**REMOTE_ENV, name: secret if name.startswith("CGW_CLIENT_") else "x" + secret[:5]})
        assert "SECRET-VALUE" not in str(caught.value)
    with pytest.raises(config.ConfigError) as caught:
        config.load_remote({**REMOTE_ENV, "CGW_CLIENT_COPY": PSK_TEXT})
    assert PSK_TEXT not in str(caught.value)


# --- client names and their variables --------------------------------------------------

@pytest.mark.parametrize("name,variable", [
    ("laptop", "CGW_CLIENT_LAPTOP"), ("work-laptop-2", "CGW_CLIENT_WORK_LAPTOP_2"), ("a" * 40, "CGW_CLIENT_" + "A" * 40),
])
def test_a_client_name_maps_to_one_variable_and_back(name, variable):
    assert config.client_variable(name) == variable
    assert config.client_name(variable) == name


@pytest.mark.parametrize("name", ["", "Laptop", "work_laptop", "-laptop", "laptop-", "a--b", "a b", "a" * 41, "é"])
def test_a_client_name_outside_the_rules_is_refused(name):
    with pytest.raises(config.ConfigError, match="client name"):
        config.client_variable(name)


# --- local: an owner-only file ---------------------------------------------------------

def test_local_settings_are_built_from_the_file(tmp_path):
    loaded = config.load_local(write_local(tmp_path))
    assert loaded.settings.remote_url == "https://gateway.example.com"
    assert (loaded.settings.kid, loaded.settings.psk, loaded.settings.local_key) == ("poc-1", PSK, LOCAL_KEY)
    assert (loaded.settings.proxy, loaded.settings.ca_bundle) == (None, None)
    assert (loaded.host, loaded.port) == ("127.0.0.1", 8318)


def test_local_proxy_ca_and_port_are_optional_settings(tmp_path):
    content = {**LOCAL_FILE, "proxy": "http://proxy.corp:8080", "ca_bundle": "/etc/ssl/corp.pem", "port": 9318}
    loaded = config.load_local(write_local(tmp_path, content))
    assert (loaded.settings.proxy, loaded.settings.ca_bundle, loaded.port) == (
        "http://proxy.corp:8080", "/etc/ssl/corp.pem", 9318)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666])
def test_local_file_readable_by_others_is_refused(tmp_path, mode):
    with pytest.raises(config.ConfigError, match="permissions"):
        config.load_local(write_local(tmp_path, mode=mode))


def test_missing_local_file_is_refused(tmp_path):
    with pytest.raises(config.ConfigError, match="not found"):
        config.load_local(tmp_path / "absent.json")


@pytest.mark.parametrize("missing", ["remote_url", "kid", "psk", "local_key"])
def test_missing_local_field_is_named_in_the_error(tmp_path, missing):
    content = {name: value for name, value in LOCAL_FILE.items() if name != missing}
    with pytest.raises(config.ConfigError, match=missing):
        config.load_local(write_local(tmp_path, content))


def test_unknown_local_field_is_refused(tmp_path):
    with pytest.raises(config.ConfigError, match="verify"):
        config.load_local(write_local(tmp_path, {**LOCAL_FILE, "verify": False}))


@pytest.mark.parametrize("field,value", [
    ("remote_url", "http://gateway.example.com"), ("psk", "short"), ("local_key", "short"),
    ("kid", "bad kid"), ("port", 70000), ("port", "8318"), ("proxy", 5),
])
def test_invalid_local_value_is_refused(tmp_path, field, value):
    with pytest.raises(config.ConfigError, match=field):
        config.load_local(write_local(tmp_path, {**LOCAL_FILE, field: value}))


def test_local_file_that_is_not_a_json_object_is_refused(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("[]")
    os.chmod(path, 0o600)
    with pytest.raises(config.ConfigError):
        config.load_local(path)


def test_local_errors_never_contain_secret_values(tmp_path):
    content = {**LOCAL_FILE, "psk": "SECRET-VALUE-psk", "local_key": "SECRET-VALUE-key"}
    with pytest.raises(config.ConfigError) as caught:
        config.load_local(write_local(tmp_path, content))
    assert "SECRET-VALUE" not in str(caught.value)


# --- generating a fresh set of secrets -------------------------------------------------

def test_generated_secrets_are_fresh_and_well_formed():
    first, second = config.generate_secrets(), config.generate_secrets()
    assert first.psk != second.psk and first.local_key != second.local_key
    assert first.cliproxy_key != second.cliproxy_key and first.kid != second.kid
    assert len(config.decode_psk(first.psk)) == 32
    assert len(first.local_key) >= 32 and len(first.cliproxy_key) >= 32
    assert first.kid.startswith("poc-")


def test_generated_secrets_can_be_named_for_a_client():
    assert config.generate_secrets(kid="work-laptop").kid == "work-laptop"


def test_generated_secrets_load_on_both_sides(tmp_path):
    secrets = config.generate_secrets(kid="laptop")
    remote = config.load_remote({config.client_variable(secrets.kid): secrets.psk,
                                 "CGW_CLIPROXY_KEY": secrets.cliproxy_key})
    path = config.write_local(tmp_path / "nested" / "config.json", "https://gateway.example.com", secrets)
    local = config.load_local(path)
    assert remote.settings.keys == {local.settings.kid: local.settings.psk}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_write_local_refuses_to_replace_an_existing_file(tmp_path):
    secrets = config.generate_secrets()
    path = config.write_local(tmp_path / "config.json", "https://gateway.example.com", secrets)
    with pytest.raises(config.ConfigError, match="exists"):
        config.write_local(path, "https://gateway.example.com", secrets)
