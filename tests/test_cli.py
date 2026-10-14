"""Command-line entry points. Servers and the Railway CLI are injected, so nothing real starts."""
import base64
import json
import logging
import stat
import tomllib

import pytest

from cgw import cli, config, ledger

PSK_TEXT = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
REMOTE_ENV = {"CGW_KID": "poc-1", "CGW_PSK": PSK_TEXT, "CGW_CLIPROXY_KEY": "k" * 40}


class Recorder:
    """Stands in for uvicorn.run and subprocess.run."""

    def __init__(self, returncode=0):
        self.calls, self.returncode = [], returncode

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return type("Completed", (), {"returncode": self.returncode})()


def run(argv, env=None, serve=None, runner=None):
    return cli.main(argv, env=env or {}, serve=serve or Recorder(), run=runner or Recorder())


# --- init-ledger ----------------------------------------------------------------------

def test_init_ledger_creates_a_usable_ledger(tmp_path):
    path = tmp_path / "bridge" / "replay.sqlite"
    assert run(["init-ledger"], env={"CGW_LEDGER_PATH": str(path)}) == 0
    assert ledger.Ledger(path).count() == 0


def test_init_ledger_refuses_to_replace_an_existing_ledger(tmp_path, capsys):
    env = {"CGW_LEDGER_PATH": str(tmp_path / "replay.sqlite")}
    run(["init-ledger"], env=env)
    assert run(["init-ledger"], env=env) == 1
    assert "already exists" in capsys.readouterr().err


# --- remote ---------------------------------------------------------------------------

def test_remote_serves_on_all_interfaces_without_server_banner_or_access_log(tmp_path):
    path = tmp_path / "replay.sqlite"
    ledger.Ledger.create(path)
    serve = Recorder()
    assert run(["remote"], env={**REMOTE_ENV, "CGW_LEDGER_PATH": str(path), "PORT": "9001"}, serve=serve) == 0
    (_, options), = serve.calls
    assert (options["host"], options["port"]) == ("0.0.0.0", 9001)
    assert options["server_header"] is False and options["access_log"] is False


def test_remote_refuses_to_start_without_a_ledger(tmp_path, capsys):
    serve = Recorder()
    env = {**REMOTE_ENV, "CGW_LEDGER_PATH": str(tmp_path / "absent.sqlite")}
    assert run(["remote"], env=env, serve=serve) == 1
    assert serve.calls == []
    assert "ledger is missing" in capsys.readouterr().err


def test_remote_refuses_to_start_with_bad_configuration_and_does_not_print_secrets(capsys):
    serve = Recorder()
    assert run(["remote"], env={**REMOTE_ENV, "CGW_PSK": "SECRET-VALUE-bad"}, serve=serve) == 1
    assert serve.calls == []
    captured = capsys.readouterr()
    assert "CGW_PSK" in captured.err and "SECRET-VALUE" not in captured.err + captured.out


# --- local ----------------------------------------------------------------------------

def test_local_serves_on_loopback_only(tmp_path):
    path = config.write_local(tmp_path / "config.json", "https://gateway.example.com", config.generate_secrets())
    serve = Recorder()
    assert run(["local", "--config", str(path)], serve=serve) == 0
    (_, options), = serve.calls
    assert (options["host"], options["port"]) == ("127.0.0.1", 8318)
    assert options["server_header"] is False and options["access_log"] is False


def test_local_refuses_to_start_without_its_config(tmp_path, capsys):
    serve = Recorder()
    assert run(["local", "--config", str(tmp_path / "absent.json")], serve=serve) == 1
    assert serve.calls == [] and "not found" in capsys.readouterr().err


# --- bootstrap ------------------------------------------------------------------------

def test_bootstrap_writes_an_owner_only_local_config(tmp_path):
    path = tmp_path / "home" / "config.json"
    assert run(["bootstrap", "--remote-url", "https://gateway.example.com", "--config", str(path),
                "--railway-service", "gateway"]) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config.load_local(path).settings.remote_url == "https://gateway.example.com"


def test_bootstrap_sends_remote_secrets_to_railway_over_stdin_never_as_arguments(tmp_path):
    path, runner = tmp_path / "config.json", Recorder()
    run(["bootstrap", "--remote-url", "https://gateway.example.com", "--config", str(path),
         "--railway-service", "gateway"], runner=runner)
    written = json.loads(path.read_text())
    sent = {}
    for (command,), options in runner.calls:
        assert command[:3] == ["railway", "variable", "set"]
        assert "--stdin" in command and "--skip-deploys" in command
        assert command[command.index("--service") + 1] == "gateway"
        assert written["psk"] not in " ".join(command)
        sent[command[3]] = options["input"]
    assert sent == {"CGW_KID": written["kid"], "CGW_PSK": written["psk"]}


def test_bootstrap_prints_names_but_no_secret_values(tmp_path, capsys):
    path = tmp_path / "config.json"
    run(["bootstrap", "--remote-url", "https://gateway.example.com", "--config", str(path),
         "--railway-service", "gateway"])
    written, output = json.loads(path.read_text()), capsys.readouterr()
    for secret in (written["psk"], written["local_key"]):
        assert secret not in output.out + output.err
    assert "CGW_PSK" in output.out


def test_bootstrap_can_also_set_a_new_internal_key(tmp_path):
    runner = Recorder()
    run(["bootstrap", "--remote-url", "https://gateway.example.com", "--config", str(tmp_path / "config.json"),
         "--railway-service", "gateway", "--set-cliproxy-key"], runner=runner)
    assert sorted(command[3] for (command,), _ in runner.calls) == ["CGW_CLIPROXY_KEY", "CGW_KID", "CGW_PSK"]


def test_bootstrap_refuses_to_replace_existing_local_secrets(tmp_path, capsys):
    path, runner = tmp_path / "config.json", Recorder()
    arguments = ["bootstrap", "--remote-url", "https://gateway.example.com", "--config", str(path),
                 "--railway-service", "gateway"]
    run(arguments)
    assert run(arguments, runner=runner) == 1
    assert runner.calls == [] and "already exists" in capsys.readouterr().err


def test_bootstrap_removes_the_local_config_when_railway_rejects_a_variable(tmp_path, capsys):
    path = tmp_path / "config.json"
    code = run(["bootstrap", "--remote-url", "https://gateway.example.com", "--config", str(path),
                "--railway-service", "gateway"], runner=Recorder(returncode=1))
    assert code == 1
    assert not path.exists()
    assert "railway" in capsys.readouterr().err.lower()


def test_bootstrap_refuses_a_plain_http_remote(tmp_path, capsys):
    runner = Recorder()
    code = run(["bootstrap", "--remote-url", "http://gateway.example.com", "--config", str(tmp_path / "c.json"),
                "--railway-service", "gateway"], runner=runner)
    assert code == 1 and runner.calls == []
    assert not (tmp_path / "c.json").exists()


# --- install-profile ------------------------------------------------------------------

def local_config(tmp_path, port=None):
    path = config.write_local(tmp_path / "config.json", "https://gateway.example.com", config.generate_secrets())
    if port is not None:
        content = json.loads(path.read_text())
        content["port"] = port
        path.write_text(json.dumps(content))
    return path


def install_profile(tmp_path, config_path, extra=()):
    codex_home = tmp_path / "codex-home"
    code = run(["install-profile", "--config", str(config_path), *extra], env={"CODEX_HOME": str(codex_home)})
    return code, codex_home / "gateway.config.toml"


def test_install_profile_writes_a_codex_profile_pointing_at_the_local_bridge(tmp_path):
    code, profile = install_profile(tmp_path, local_config(tmp_path))
    settings = tomllib.loads(profile.read_text())
    provider = settings["model_providers"][settings["model_provider"]]
    assert code == 0
    assert provider["base_url"] == "http://127.0.0.1:8318/v1"
    assert (provider["env_key"], provider["wire_api"]) == ("CGW_LOCAL_API_KEY", "responses")
    assert (provider["request_max_retries"], provider["stream_max_retries"]) == (0, 0)
    assert provider["supports_websockets"] is False and provider["requires_openai_auth"] is False
    assert settings["model"] == "gpt-6-astra"


def test_install_profile_uses_the_port_from_the_local_config(tmp_path):
    _, profile = install_profile(tmp_path, local_config(tmp_path, port=9318))
    settings = tomllib.loads(profile.read_text())
    assert settings["model_providers"][settings["model_provider"]]["base_url"] == "http://127.0.0.1:9318/v1"


def test_install_profile_accepts_another_model(tmp_path):
    _, profile = install_profile(tmp_path, local_config(tmp_path), extra=["--model", "gpt-6-sol"])
    assert tomllib.loads(profile.read_text())["model"] == "gpt-6-sol"


def test_install_profile_is_idempotent(tmp_path):
    config_path = local_config(tmp_path)
    _, profile = install_profile(tmp_path, config_path)
    first = profile.read_text()
    code, _ = install_profile(tmp_path, config_path)
    assert code == 0 and profile.read_text() == first


def test_install_profile_refuses_to_replace_a_different_profile(tmp_path, capsys):
    config_path = local_config(tmp_path)
    _, profile = install_profile(tmp_path, config_path)
    profile.write_text("# edited by hand\n")
    code, _ = install_profile(tmp_path, config_path)
    assert code == 1
    assert profile.read_text() == "# edited by hand\n"
    assert "differs" in capsys.readouterr().err


def test_install_profile_contains_no_secret(tmp_path):
    config_path = local_config(tmp_path)
    _, profile = install_profile(tmp_path, config_path)
    written = json.loads(config_path.read_text())
    assert written["local_key"] not in profile.read_text() and written["psk"] not in profile.read_text()


def test_install_profile_needs_the_local_config(tmp_path, capsys):
    code, profile = install_profile(tmp_path, tmp_path / "absent.json")
    assert code == 1 and not profile.exists()
    assert "not found" in capsys.readouterr().err


def test_http_client_libraries_do_not_log_requests(tmp_path):
    # Their per-request INFO lines would put every outer and upstream URL in the logs.
    logging.getLogger("httpx").setLevel(logging.NOTSET)
    logging.getLogger("httpcore").setLevel(logging.NOTSET)
    run(["init-ledger"], env={"CGW_LEDGER_PATH": str(tmp_path / "replay.sqlite")})
    # The level must be set on these loggers themselves: the root logger runs at INFO in production.
    assert logging.getLogger("httpx").level >= logging.WARNING
    assert logging.getLogger("httpcore").level >= logging.WARNING


def test_unknown_command_exits_with_usage():
    with pytest.raises(SystemExit):
        run(["nonsense"])
