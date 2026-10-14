"""Command-line entry points. Servers and the Railway CLI are injected, so nothing real starts."""
import base64
import json
import logging
import stat
import tomllib

import pytest

from cgw import cli, config, server

PSK_TEXT = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
REMOTE_ENV = {"CGW_CLIENT_POC_1": PSK_TEXT, "CGW_CLIPROXY_KEY": "k" * 40}
GATEWAY = "https://gateway.example.com"


class Recorder:
    """Stands in for uvicorn.run and subprocess.run."""

    def __init__(self, returncode=0):
        self.calls, self.returncode = [], returncode

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return type("Completed", (), {"returncode": self.returncode})()


class FakeRailway:
    """Stands in for the Railway CLI: keeps one service's variables and records every command."""

    def __init__(self, variables=None, failing=()):
        self.variables = dict({"PORT": "8080"} if variables is None else variables)
        self.failing, self.commands = set(failing), []

    def __call__(self, command, **options):
        self.commands.append((command, options))
        verb = " ".join(command[1:3]) if command[1] == "variable" else command[1]
        if verb in self.failing:
            return type("Completed", (), {"returncode": 1, "stdout": "", "stderr": "refused"})()
        stdout = ""
        if verb == "variable list":
            stdout = json.dumps(self.variables)
        elif verb == "variable set":
            self.variables[command[3]] = options["input"]
        elif verb == "variable delete":
            del self.variables[command[3]]
        return type("Completed", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    @property
    def verbs(self):
        return [" ".join(command[1:3]) if command[1] == "variable" else command[1] for command, _ in self.commands]


def run(argv, env=None, serve=None, runner=None):
    return cli.main(argv, env=env or {}, serve=serve or Recorder(), run=runner or Recorder())


# --- remote ---------------------------------------------------------------------------

def test_remote_serves_on_all_interfaces_without_server_banner_or_access_log(tmp_path):
    serve = Recorder()
    assert run(["remote"], env={**REMOTE_ENV, "PORT": "9001"}, serve=serve) == 0
    (_, options), = serve.calls
    assert (options["host"], options["port"]) == ("0.0.0.0", 9001)
    assert options["server_header"] is False and options["access_log"] is False


def test_remote_caps_the_number_of_concurrent_connections(tmp_path):
    serve = Recorder()
    run(["remote"], env=REMOTE_ENV, serve=serve)
    (_, options), = serve.calls
    assert options["limit_concurrency"] == 1024
    assert options["http"] is server.HeadTimeoutProtocol


def test_remote_starts_with_no_storage_of_its_own(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    serve = Recorder()
    assert run(["remote"], env=REMOTE_ENV, serve=serve) == 0
    assert len(serve.calls) == 1
    assert list(tmp_path.iterdir()) == []


def test_the_init_ledger_command_no_longer_exists():
    with pytest.raises(SystemExit):
        run(["init-ledger"])


def test_remote_refuses_to_start_with_bad_configuration_and_does_not_print_secrets(capsys):
    serve = Recorder()
    assert run(["remote"], env={**REMOTE_ENV, "CGW_CLIENT_POC_1": "SECRET-VALUE-bad"}, serve=serve) == 1
    assert serve.calls == []
    captured = capsys.readouterr()
    assert "CGW_CLIENT_POC_1" in captured.err and "SECRET-VALUE" not in captured.err + captured.out


def test_remote_says_when_the_old_single_key_variables_are_still_set(capsys):
    serve = Recorder()
    assert run(["remote"], env={**REMOTE_ENV, "CGW_KID": "old", "CGW_PSK": "SECRET-VALUE-old"}, serve=serve) == 0
    captured = capsys.readouterr()
    assert "CGW_KID" in captured.err and "CGW_PSK" in captured.err
    assert "SECRET-VALUE" not in captured.err + captured.out


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


# --- bootstrap: a new gateway's first client, on this machine ---------------------------

def bootstrap(path, runner, extra=(), name="laptop", url=GATEWAY):
    return run(["bootstrap", "--remote-url", url, "--config", str(path), "--railway-service", "gateway",
                "--client-name", name, *extra], runner=runner)


def test_bootstrap_writes_an_owner_only_local_config_named_for_the_client(tmp_path):
    path = tmp_path / "home" / "config.json"
    assert bootstrap(path, FakeRailway()) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = config.load_local(path)
    assert (loaded.settings.remote_url, loaded.settings.kid) == (GATEWAY, "laptop")


def test_bootstrap_sends_the_client_key_to_railway_over_stdin_never_as_an_argument(tmp_path):
    path, railway = tmp_path / "config.json", FakeRailway()
    bootstrap(path, railway)
    written = json.loads(path.read_text())
    for command, options in railway.commands:
        assert command[:3] == ["railway", "variable", "set"]
        assert "--stdin" in command and "--skip-deploys" in command
        assert command[command.index("--service") + 1] == "gateway"
        assert written["psk"] not in " ".join(command)
    assert railway.variables == {"PORT": "8080", "CGW_CLIENT_LAPTOP": written["psk"]}


def test_bootstrap_leaves_the_deploy_to_the_next_step(tmp_path):
    railway = FakeRailway()
    bootstrap(tmp_path / "config.json", railway)
    assert "redeploy" not in railway.verbs


def test_bootstrap_prints_names_but_no_secret_values(tmp_path, capsys):
    path = tmp_path / "config.json"
    bootstrap(path, FakeRailway())
    written, output = json.loads(path.read_text()), capsys.readouterr()
    for secret in (written["psk"], written["local_key"]):
        assert secret not in output.out + output.err
    assert "CGW_CLIENT_LAPTOP" in output.out


def test_bootstrap_can_also_set_a_new_internal_key(tmp_path):
    railway = FakeRailway()
    bootstrap(tmp_path / "config.json", railway, extra=["--set-cliproxy-key"])
    assert sorted(railway.variables) == ["CGW_CLIENT_LAPTOP", "CGW_CLIPROXY_KEY", "PORT"]


def test_bootstrap_refuses_to_replace_existing_local_secrets(tmp_path, capsys):
    path = tmp_path / "config.json"
    bootstrap(path, FakeRailway())
    railway = FakeRailway()
    assert bootstrap(path, railway) == 1
    assert railway.commands == [] and "already exists" in capsys.readouterr().err


def test_bootstrap_removes_the_local_config_when_railway_rejects_a_variable(tmp_path, capsys):
    path = tmp_path / "config.json"
    assert bootstrap(path, FakeRailway(failing={"variable set"})) == 1
    assert not path.exists()
    assert "railway" in capsys.readouterr().err.lower()


def test_bootstrap_refuses_a_plain_http_remote(tmp_path):
    railway = FakeRailway()
    assert bootstrap(tmp_path / "c.json", railway, url="http://gateway.example.com") == 1
    assert railway.commands == [] and not (tmp_path / "c.json").exists()


def test_bootstrap_refuses_a_client_name_outside_the_rules(tmp_path, capsys):
    railway = FakeRailway()
    assert bootstrap(tmp_path / "c.json", railway, name="Work_Laptop") == 1
    assert railway.commands == [] and not (tmp_path / "c.json").exists()
    assert "client name" in capsys.readouterr().err


def test_bootstrap_needs_a_client_name(tmp_path):
    with pytest.raises(SystemExit):
        run(["bootstrap", "--remote-url", GATEWAY, "--config", str(tmp_path / "c.json"),
             "--railway-service", "gateway"], runner=FakeRailway())


# --- add-client: a key for one more machine ---------------------------------------------

def admin_config(tmp_path):
    """The admin's own working config, which add-client takes the gateway address from."""
    return config.write_local(tmp_path / "admin" / "config.json", GATEWAY, config.generate_secrets(kid="admin"))


def add_client(tmp_path, railway, name="laptop-2", extra=(), service=True, out=True):
    arguments = ["add-client", name, "--config", str(admin_config(tmp_path))]
    if out:
        arguments += ["--out", str(tmp_path / "issued" / (name + ".json"))]
    if service:
        arguments += ["--railway-service", "gateway"]
    return run([*arguments, *extra], runner=railway)


def issued(tmp_path, name="laptop-2"):
    return tmp_path / "issued" / (name + ".json")


def test_add_client_writes_an_owner_only_config_for_the_new_machine(tmp_path):
    assert add_client(tmp_path, FakeRailway()) == 0
    path = issued(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = config.load_local(path)
    assert (loaded.settings.remote_url, loaded.settings.kid) == (GATEWAY, "laptop-2")


def test_the_gateway_accepts_the_new_client_and_keeps_the_others(tmp_path):
    railway = FakeRailway({"CGW_CLIENT_ADMIN": PSK_TEXT, "CGW_CLIPROXY_KEY": "k" * 40})
    add_client(tmp_path, railway)
    keys = config.load_remote(railway.variables).settings.keys
    assert keys["laptop-2"] == config.load_local(issued(tmp_path)).settings.psk
    assert keys["admin"] == bytes(range(32))


def test_add_client_sends_the_key_over_stdin_and_then_redeploys(tmp_path):
    railway = FakeRailway()
    add_client(tmp_path, railway)
    assert railway.verbs == ["variable list", "variable set", "redeploy"]
    (set_command, options), = [(c, o) for c, o in railway.commands if c[1:3] == ["variable", "set"]]
    assert set_command[3] == "CGW_CLIENT_LAPTOP_2" and "--stdin" in set_command and "--skip-deploys" in set_command
    assert options["input"] not in " ".join(set_command)
    redeploy, _ = railway.commands[-1]
    assert redeploy == ["railway", "redeploy", "--service", "gateway", "--yes"]


def test_add_client_prints_where_the_file_is_but_no_secret_values(tmp_path, capsys):
    add_client(tmp_path, FakeRailway())
    written, output = json.loads(issued(tmp_path).read_text()), capsys.readouterr()
    for secret in (written["psk"], written["local_key"]):
        assert secret not in output.out + output.err
    assert str(issued(tmp_path)) in output.out and "CGW_CLIENT_LAPTOP_2" in output.out


def test_add_client_writes_into_the_clients_folder_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "DEFAULT_CLIENTS_DIR", tmp_path / "clients")
    assert add_client(tmp_path, FakeRailway(), out=False) == 0
    path = tmp_path / "clients" / "laptop-2.json"
    assert config.load_local(path).settings.kid == "laptop-2"
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_add_client_can_be_given_the_gateway_address(tmp_path):
    out = tmp_path / "laptop-2.json"
    assert run(["add-client", "laptop-2", "--remote-url", "https://other.example.com", "--out", str(out),
                "--config", str(tmp_path / "absent.json"), "--railway-service", "gateway"], runner=FakeRailway()) == 0
    assert config.load_local(out).settings.remote_url == "https://other.example.com"


def test_add_client_needs_an_address_when_this_machine_has_no_config(tmp_path, capsys):
    railway = FakeRailway()
    code = run(["add-client", "laptop-2", "--out", str(tmp_path / "x.json"), "--config", str(tmp_path / "absent.json"),
                "--railway-service", "gateway"], runner=railway)
    assert code == 1 and railway.commands == []
    assert "--remote-url" in capsys.readouterr().err


def test_add_client_refuses_a_name_already_in_use(tmp_path, capsys):
    railway = FakeRailway({"CGW_CLIENT_LAPTOP_2": PSK_TEXT})
    assert add_client(tmp_path, railway) == 1
    assert railway.variables["CGW_CLIENT_LAPTOP_2"] == PSK_TEXT and "variable set" not in railway.verbs
    assert not issued(tmp_path).exists()
    assert "--replace" in capsys.readouterr().err


def test_add_client_with_replace_issues_a_new_key_for_an_existing_name(tmp_path):
    railway = FakeRailway({"CGW_CLIENT_LAPTOP_2": PSK_TEXT})
    assert add_client(tmp_path, railway, extra=["--replace"]) == 0
    assert railway.variables["CGW_CLIENT_LAPTOP_2"] == json.loads(issued(tmp_path).read_text())["psk"] != PSK_TEXT


def test_add_client_refuses_a_name_outside_the_rules(tmp_path, capsys):
    railway = FakeRailway()
    assert add_client(tmp_path, railway, name="Laptop 2") == 1
    assert railway.commands == [] and not (tmp_path / "issued").exists()
    assert "client name" in capsys.readouterr().err


def test_add_client_writes_nothing_when_railway_cannot_list_the_variables(tmp_path, capsys):
    railway = FakeRailway(failing={"variable list"})
    assert add_client(tmp_path, railway) == 1
    assert not issued(tmp_path).exists() and railway.verbs == ["variable list"]
    assert "railway" in capsys.readouterr().err.lower()


def test_add_client_removes_the_file_when_railway_rejects_the_key(tmp_path):
    railway = FakeRailway(failing={"variable set"})
    assert add_client(tmp_path, railway) == 1
    assert not issued(tmp_path).exists() and "redeploy" not in railway.verbs


def test_add_client_says_how_to_finish_when_the_redeploy_fails(tmp_path, capsys):
    railway = FakeRailway(failing={"redeploy"})
    assert add_client(tmp_path, railway) == 1
    assert issued(tmp_path).exists() and "CGW_CLIENT_LAPTOP_2" in railway.variables
    assert "railway redeploy --service gateway --yes" in capsys.readouterr().err


def test_add_client_without_railway_writes_the_file_and_names_the_variable_to_add(tmp_path, capsys):
    runner = Recorder()
    assert add_client(tmp_path, runner, service=False) == 0
    written, output = json.loads(issued(tmp_path).read_text()), capsys.readouterr()
    assert runner.calls == []
    assert "CGW_CLIENT_LAPTOP_2" in output.out and written["psk"] not in output.out + output.err


def test_add_client_carries_proxy_settings_into_the_new_file(tmp_path):
    add_client(tmp_path, FakeRailway(), extra=["--proxy", "http://proxy.corp:8080", "--ca-bundle", "/etc/corp.pem"])
    settings = config.load_local(issued(tmp_path)).settings
    assert (settings.proxy, settings.ca_bundle) == ("http://proxy.corp:8080", "/etc/corp.pem")


# --- remove-client and list-clients -----------------------------------------------------

TWO_CLIENTS = {"CGW_CLIENT_ADMIN": PSK_TEXT, "CGW_CLIENT_LAPTOP_2": "x" * 43, "CGW_CLIPROXY_KEY": "k" * 40}


def test_remove_client_deletes_its_variable_and_redeploys(tmp_path):
    railway = FakeRailway(TWO_CLIENTS)
    assert run(["remove-client", "laptop-2", "--railway-service", "gateway"], runner=railway) == 0
    assert "CGW_CLIENT_LAPTOP_2" not in railway.variables and "CGW_CLIENT_ADMIN" in railway.variables
    assert railway.verbs == ["variable list", "variable delete", "redeploy"]
    delete, options = railway.commands[1]
    assert delete == ["railway", "variable", "delete", "CGW_CLIENT_LAPTOP_2", "--service", "gateway"]


def test_remove_client_refuses_a_client_that_does_not_exist(tmp_path, capsys):
    railway = FakeRailway(TWO_CLIENTS)
    assert run(["remove-client", "laptop-3", "--railway-service", "gateway"], runner=railway) == 1
    assert railway.verbs == ["variable list"] and "laptop-3" in capsys.readouterr().err


def test_remove_client_refuses_to_remove_the_last_client(tmp_path, capsys):
    railway = FakeRailway({"CGW_CLIENT_ADMIN": PSK_TEXT, "CGW_CLIPROXY_KEY": "k" * 40})
    assert run(["remove-client", "admin", "--railway-service", "gateway"], runner=railway) == 1
    assert "CGW_CLIENT_ADMIN" in railway.variables
    assert "only client" in capsys.readouterr().err


def test_remove_client_warns_that_the_client_still_works_until_a_redeploy(tmp_path, capsys):
    railway = FakeRailway(TWO_CLIENTS, failing={"redeploy"})
    assert run(["remove-client", "laptop-2", "--railway-service", "gateway"], runner=railway) == 1
    error = capsys.readouterr().err
    assert "still" in error and "railway redeploy --service gateway --yes" in error


def test_remove_client_reports_a_refused_delete(tmp_path, capsys):
    railway = FakeRailway(TWO_CLIENTS, failing={"variable delete"})
    assert run(["remove-client", "laptop-2", "--railway-service", "gateway"], runner=railway) == 1
    assert "redeploy" not in railway.verbs and "railway" in capsys.readouterr().err.lower()


def test_list_clients_prints_names_and_never_values(capsys):
    railway = FakeRailway({**TWO_CLIENTS, "CGW_CLIENT_bad": "SECRET-VALUE-1"})
    assert run(["list-clients", "--railway-service", "gateway"], runner=railway) == 0
    output = capsys.readouterr().out
    assert output.splitlines()[:2] == ["admin", "laptop-2"]
    assert "CGW_CLIENT_bad" in output
    assert PSK_TEXT not in output and "SECRET-VALUE" not in output and "k" * 40 not in output


def test_list_clients_points_out_the_old_single_key_variables(capsys):
    railway = FakeRailway({**TWO_CLIENTS, "CGW_KID": "poc-1", "CGW_PSK": PSK_TEXT})
    run(["list-clients", "--railway-service", "gateway"], runner=railway)
    output = capsys.readouterr().out
    assert "CGW_KID" in output and "CGW_PSK" in output and PSK_TEXT not in output


def test_list_clients_reports_a_railway_failure(capsys):
    assert run(["list-clients", "--railway-service", "gateway"], runner=FakeRailway(failing={"variable list"})) == 1
    assert "railway" in capsys.readouterr().err.lower()


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
    run(["local", "--config", str(tmp_path / "absent.json")])
    # The level must be set on these loggers themselves: the root logger runs at INFO in production.
    assert logging.getLogger("httpx").level >= logging.WARNING
    assert logging.getLogger("httpcore").level >= logging.WARNING


def test_unknown_command_exits_with_usage():
    with pytest.raises(SystemExit):
        run(["nonsense"])


# --- an env file instead of Railway: any Docker host -----------------------------------

def read_env_file(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))


def test_bootstrap_into_an_env_file_writes_the_gateway_half_owner_only(tmp_path, capsys):
    env_file, path = tmp_path / "server" / "gateway.env", tmp_path / "config.json"
    assert run(["bootstrap", "--remote-url", GATEWAY, "--config", str(path), "--env-file", str(env_file),
                "--client-name", "laptop", "--set-cliproxy-key"]) == 0
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    values = read_env_file(env_file)
    assert values["CGW_CLIENT_LAPTOP"] == json.loads(path.read_text())["psk"]
    keys = config.load_remote(values).settings.keys
    assert keys["laptop"] == config.load_local(path).settings.psk
    output = capsys.readouterr()
    assert values["CGW_CLIENT_LAPTOP"] not in output.out + output.err
    assert values["CGW_CLIPROXY_KEY"] not in output.out + output.err


def test_add_and_remove_client_in_an_env_file_keep_everything_else(tmp_path, capsys):
    env_file = tmp_path / "gateway.env"
    env_file.write_text("# gateway settings\nCGW_CLIPROXY_KEY=" + "k" * 40 + "\nCGW_CLIENT_ADMIN=" + PSK_TEXT + "\n")
    env_file.chmod(0o600)
    arguments = ["add-client", "laptop-2", "--config", str(admin_config(tmp_path)), "--out", str(issued(tmp_path)),
                 "--env-file", str(env_file)]
    assert run(arguments) == 0
    values = read_env_file(env_file)
    assert values["CGW_CLIENT_LAPTOP_2"] == json.loads(issued(tmp_path).read_text())["psk"]
    assert values["CGW_CLIENT_ADMIN"] == PSK_TEXT and env_file.read_text().startswith("# gateway settings\n")
    assert "restart" in capsys.readouterr().out
    assert run(["remove-client", "laptop-2", "--env-file", str(env_file)]) == 0
    assert "CGW_CLIENT_LAPTOP_2" not in read_env_file(env_file)
    assert run(["remove-client", "admin", "--env-file", str(env_file)]) == 1
    assert "only client" in capsys.readouterr().err


def test_list_clients_reads_an_env_file(tmp_path, capsys):
    env_file = tmp_path / "gateway.env"
    env_file.write_text("CGW_CLIENT_ADMIN=" + PSK_TEXT + "\nCGW_CLIENT_LAPTOP_2=" + "x" * 43 + "\n")
    env_file.chmod(0o600)
    assert run(["list-clients", "--env-file", str(env_file)]) == 0
    output = capsys.readouterr().out
    assert output.splitlines()[:2] == ["admin", "laptop-2"] and PSK_TEXT not in output


def test_an_env_file_readable_by_others_is_refused(tmp_path, capsys):
    env_file = tmp_path / "gateway.env"
    env_file.write_text("CGW_CLIENT_ADMIN=" + PSK_TEXT + "\n")
    env_file.chmod(0o644)
    assert run(["list-clients", "--env-file", str(env_file)]) == 1
    assert "chmod 600" in capsys.readouterr().err


def test_an_env_file_and_railway_cannot_both_be_named(tmp_path):
    with pytest.raises(SystemExit):
        run(["list-clients", "--env-file", str(tmp_path / "g.env"), "--railway-service", "gateway"])


def test_list_and_remove_need_somewhere_to_look(tmp_path, capsys):
    assert run(["list-clients"]) == 1
    assert "--env-file" in capsys.readouterr().err


def test_env_file_writes_never_go_through_a_planted_temporary_file(tmp_path):
    # A file or symlink waiting at a predictable temporary name must not receive the keys.
    env_file, elsewhere = tmp_path / "gateway.env", tmp_path / "elsewhere.txt"
    elsewhere.write_text("")
    elsewhere.chmod(0o644)
    (tmp_path / "gateway.env.tmp").symlink_to(elsewhere)
    assert run(["bootstrap", "--remote-url", GATEWAY, "--config", str(tmp_path / "c.json"),
                "--env-file", str(env_file), "--client-name", "laptop"]) == 0
    assert elsewhere.read_text() == ""
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600 and not env_file.is_symlink()
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".gateway.env")] == []
