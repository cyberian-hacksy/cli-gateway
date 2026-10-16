"""The admission scan stays bounded, including provisioning before any writes."""
import base64

import pytest

from cgw import config, remote_bridge
from test_cli import FakeRailway, GATEWAY, run


def variables(count):
    return {("CGW_CLIENT_" if i % 2 == 0 else "CGW_ADMIN_") + "M%d" % i:
            base64.urlsafe_b64encode(bytes([i + 1]) * 32).rstrip(b"=").decode()
            for i in range(count)}


def test_remote_key_limit_counts_clients_and_admins():
    env = {**variables(64), "CGW_CLIPROXY_KEY": "k" * 40,
           "CGW_CLIPROXY_MANAGEMENT_KEY": "m" * 40}
    assert len(config.load_remote(env).settings.keys) == 64
    with pytest.raises(config.ConfigError, match="64"):
        config.load_remote({**env, "CGW_CLIENT_EXTRA": base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")})


@pytest.mark.parametrize("keys", [
    {"m%d" % i: bytes([i + 1]) * 32 for i in range(65)},
    {"first": b"a" * 32, "second": b"a" * 32},
])
def test_app_rejects_65_keys_and_duplicate_psks(keys):
    with pytest.raises(ValueError):
        remote_bridge.create_app(remote_bridge.Settings(keys, "http://127.0.0.1:8317", "k" * 40))


@pytest.mark.parametrize("store_kind", ["railway", "env-file"])
@pytest.mark.parametrize("command,count", [("add-client", 64), ("grant-admin", 64), ("bootstrap", 63)])
def test_provisioning_at_capacity_writes_nothing(tmp_path, store_kind, command, count):
    existing = variables(count)
    railway = FakeRailway(existing)
    env_file = tmp_path / "gateway.env"
    if store_kind == "env-file":
        env_file.write_text("".join("%s=%s\n" % item for item in existing.items()))
        env_file.chmod(0o600)
        store = ["--env-file", str(env_file)]
    else:
        store = ["--railway-service", "gateway"]
    before = env_file.read_bytes() if env_file.exists() else None
    arguments = [command, *([] if command == "bootstrap" else ["extra"]), *store,
                 "--remote-url", GATEWAY, "--config", str(tmp_path / "config.json")]
    if command == "bootstrap":
        arguments += ["--client-name", "extra"]
    elif command == "add-client":
        arguments += ["--out", str(tmp_path / "issued.json")]
    assert run(arguments, runner=railway, ask=lambda _: pytest.fail("must check capacity before passphrase")) == 1
    assert railway.variables == existing
    assert all(verb == "variable list" for verb in railway.verbs)
    assert set(path.name for path in tmp_path.iterdir()) == ({"gateway.env"} if before else set())
    if before:
        assert env_file.read_bytes() == before


@pytest.mark.parametrize("command,name", [("add-client", "m0"), ("grant-admin", "m1")])
def test_replacing_a_key_at_capacity_is_allowed(tmp_path, command, name):
    railway = FakeRailway({**variables(64), "CGW_CLIPROXY_MANAGEMENT_KEY": "m" * 40})
    arguments = [command, name, "--replace", "--railway-service", "gateway", "--remote-url", GATEWAY,
                 "--config", str(tmp_path / "config.json")]
    if command == "add-client":
        arguments += ["--out", str(tmp_path / "issued.json")]
    assert run(arguments, runner=railway) == 0
    assert len([name for name in railway.variables if name.startswith(("CGW_CLIENT_", "CGW_ADMIN_"))]) == 64


def test_bootstrap_without_admin_fits_last_slot(tmp_path):
    railway = FakeRailway(variables(63))
    assert run(["bootstrap", "--client-name", "extra", "--no-admin", "--remote-url", GATEWAY,
                "--config", str(tmp_path / "config.json"), "--railway-service", "gateway"], runner=railway) == 0
    assert len(railway.variables) == 64
