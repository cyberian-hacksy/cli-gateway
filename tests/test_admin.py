"""Signing the gateway in to subscriptions with an admin key: commands, catcher and local page."""
import asyncio
import json
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from cgw import admin, admin_page, cli, remote_bridge
from harness import ServerThread, wait_until
from synthetic_upstream import INTERNAL_KEY, MANAGEMENT_KEY, Upstream

PSK, ADMIN_PSK = bytes(range(32)), bytes(range(3, 35))
PASSPHRASE = "a long admin passphrase"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class gateway:
    """A remote bridge with one client and one admin key, in front of a synthetic upstream."""

    def __init__(self, management_key=MANAGEMENT_KEY):
        self.management_key = management_key

    def __enter__(self):
        self.redirect_port = free_port()
        self.upstream = Upstream(redirect_port=self.redirect_port)
        self.upstream_server = ServerThread(self.upstream.app).__enter__()
        settings = remote_bridge.Settings(
            keys={"main": PSK, "admin_main": ADMIN_PSK}, upstream_url=self.upstream_server.url,
            upstream_key=INTERNAL_KEY, admins=frozenset({"admin_main"}), management_key=self.management_key)
        self.remote = ServerThread(remote_bridge.create_app(settings)).__enter__()
        self.key = admin.AdminKey(name="main", remote_url=self.remote.url, kid="admin_main", psk=ADMIN_PSK)
        return self

    def __exit__(self, *exc_info):
        self.remote.__exit__(*exc_info)
        self.upstream_server.__exit__(*exc_info)


def provider_redirect(url, code="one-time-code"):
    """What the provider does once the person has signed in: send the browser to the redirect_uri."""
    query = parse_qs(urlsplit(url).query)
    target = "%s?code=%s&state=%s" % (query["redirect_uri"][0], code, query["state"][0]) if code else \
        "%s?error=access_denied&state=%s" % (query["redirect_uri"][0], query["state"][0])
    target = target.replace("localhost", "127.0.0.1")
    for _ in range(50):
        try:
            return httpx.get(target, timeout=5)
        except httpx.ConnectError:
            time.sleep(0.05)
    raise AssertionError("nothing listened on " + target)


def browser(code="one-time-code"):
    """A fake browser: opening the sign-in address leads, after a moment, to the provider's redirect."""
    opened = []

    def open_url(url):
        opened.append(url)
        threading.Thread(target=provider_redirect, args=(url, code), daemon=True).start()
    open_url.opened = opened
    return open_url


def sign_in(key, provider, open_browser, **options):
    async def run():
        async with admin.AdminClient(key) as client:
            return await admin.run_sign_in(client, provider, open_browser, report=lambda message: None,
                                           poll_seconds=0.05, timeout=10, **options)
    return asyncio.run(run())


# --- the sign-in, through the gateway --------------------------------------------------

def test_a_sign_in_is_caught_here_and_completed_on_the_gateway():
    with gateway() as gw:
        assert sign_in(gw.key, "anthropic", browser()) == "Claude"
        assert "anthropic-new.json" in gw.upstream.sign_ins
        callback = next(call for call in gw.upstream.calls if call["path"].endswith("/oauth-callback"))
        sent = json.loads(callback["body"])
        assert sent["provider"] == "anthropic" and "code=one-time-code" in sent["redirect_url"]
        assert all(call["headers"]["authorization"] == "Bearer " + MANAGEMENT_KEY for call in gw.upstream.calls)


def test_a_refused_sign_in_is_reported_as_failed():
    with gateway() as gw:
        with pytest.raises(admin.AdminError, match="failed"):
            sign_in(gw.key, "codex", browser(code=None))
        assert set(gw.upstream.sign_ins) == {"codex-someone.json"}


def test_when_the_redirect_port_is_taken_the_address_can_be_pasted():
    with gateway() as gw:
        squatter = socket.socket()
        squatter.bind(("127.0.0.1", gw.redirect_port))
        squatter.listen()
        try:
            opened = []

            async def pasted():
                url = opened[0]
                query = parse_qs(urlsplit(url).query)
                return "%s?code=pasted&state=%s" % (query["redirect_uri"][0], query["state"][0])
            assert sign_in(gw.key, "antigravity", opened.append, pasted=pasted) == admin.PROVIDERS["antigravity"]
        finally:
            squatter.close()


def test_a_machine_without_admin_rights_cannot_sign_the_gateway_in():
    with gateway() as gw:
        not_admin = admin.AdminKey(name="main", remote_url=gw.remote.url, kid="main", psk=PSK)
        with pytest.raises(admin.AdminError, match="refused: rejected"):
            sign_in(not_admin, "anthropic", browser())
        assert gw.upstream.calls == []


def test_the_catcher_answers_only_its_own_path():
    async def run():
        port = free_port()
        catcher = admin.CallbackCatcher("http://localhost:%d/callback" % port)
        await catcher.start()
        try:
            async with httpx.AsyncClient() as client:
                assert (await client.get("http://127.0.0.1:%d/favicon.ico" % port)).status_code == 404
                assert not catcher.caught.done()
                response = await client.get("http://127.0.0.1:%d/callback?code=c&state=s" % port)
                assert response.status_code == 200 and "close this tab" in response.text
            assert await catcher.caught == "http://localhost:%d/callback?code=c&state=s" % port
        finally:
            await catcher.close()
    asyncio.run(run())


@pytest.mark.parametrize("redirect", ["https://attacker.example.com/callback", "http://attacker.example.com:54545/callback",
                                      "https://localhost:54545/callback", "http://10.0.0.5:54545/callback",
                                      "http://localhost/callback"])
def test_a_redirect_to_anything_but_a_loopback_port_is_refused(redirect):
    async def run():
        with pytest.raises(admin.AdminError, match="not a loopback"):
            admin.CallbackCatcher(redirect)
    asyncio.run(run())


def test_the_key_file_itself_refuses_a_short_passphrase(tmp_path):
    with pytest.raises(admin.AdminError, match="at least"):
        admin.write_admin_key(tmp_path / "admin.json", admin.AdminKey("m", "https://g.example.com", "admin_m", PSK), "short")
    assert not (tmp_path / "admin.json").exists()


def test_aliases_name_the_providers():
    assert [admin.provider_id(name) for name in ("claude", "google", "gemini", "openai", "codex")] == \
        ["anthropic", "antigravity", "antigravity", "codex", "codex"]
    with pytest.raises(admin.AdminError, match="unknown provider"):
        admin.provider_id("myspace")


# --- the commands ---------------------------------------------------------------------

def write_key(tmp_path, key):
    return admin.write_admin_key(tmp_path / "admin.json", key, PASSPHRASE)


def command(tmp_path, argv, browse=None):
    return cli.main([*argv, "--config", str(tmp_path / "config.json")], env={},
                    ask=lambda prompt: PASSPHRASE, browse=browse or (lambda url: None))


def test_the_sign_in_command(tmp_path, capsys):
    with gateway() as gw:
        write_key(tmp_path, gw.key)
        assert command(tmp_path, ["sign-in", "claude"], browse=browser()) == 0
    output = capsys.readouterr().out
    assert "signed in: Claude" in output and "https://sign-in.example.com/" in output


def test_the_subscriptions_command_shows_no_tokens(tmp_path, capsys):
    with gateway() as gw:
        write_key(tmp_path, gw.key)
        assert command(tmp_path, ["subscriptions"]) == 0
    output = capsys.readouterr().out
    assert "codex-someone.json" in output and "someone@example.com" in output
    assert "SECRET-ID-TOKEN" not in output


def test_the_sign_out_command(tmp_path):
    with gateway() as gw:
        write_key(tmp_path, gw.key)
        assert command(tmp_path, ["sign-out", "codex-someone.json"]) == 0
        assert gw.upstream.sign_ins == {}


def test_admin_commands_refuse_a_wrong_passphrase_before_contacting_the_gateway(tmp_path, capsys):
    with gateway() as gw:
        write_key(tmp_path, gw.key)
        code = cli.main(["subscriptions", "--config", str(tmp_path / "config.json")], env={},
                        ask=lambda prompt: "not the passphrase")
        assert code == 1 and gw.upstream.calls == []
    assert "wrong passphrase" in capsys.readouterr().err


# --- the local page -------------------------------------------------------------------

class page:
    """The admin page on a real loopback port, with its one-time token."""

    def __init__(self, gw, browse=None):
        self.gw, self.browse = gw, browse or (lambda url: None)

    def __enter__(self):
        self.token = "one-time-token-for-tests"
        self.port = free_port()
        app = admin_page.create_app(admin.AdminClient(self.gw.key), self.port, self.token, self.browse)
        self.server = ServerThread(app, port=self.port).__enter__()
        self.base = "http://127.0.0.1:%d" % self.port
        return self

    def __exit__(self, *exc_info):
        self.server.__exit__(*exc_info)

    def session(self):
        client = httpx.Client(base_url=self.base, timeout=10)
        response = client.get("/?token=" + self.token, follow_redirects=False)
        assert response.status_code == 303
        return client



def act(client, base, path, body):
    return client.post(path, json=body, headers={"Origin": base, "X-CGW-Admin": "1"})


def test_the_page_needs_the_one_time_link():
    with gateway() as gw, page(gw) as admin_ui:
        assert httpx.get(admin_ui.base + "/").status_code == 403
        assert httpx.get(admin_ui.base + "/api/sign-ins").status_code == 403
        assert httpx.get(admin_ui.base + "/?token=wrong").status_code == 403
        client = admin_ui.session()
        assert client.get("/").status_code == 200
        assert "Gateway sign-ins" in client.get("/").text
        # The link works once.
        assert httpx.get(admin_ui.base + "/?token=" + admin_ui.token, follow_redirects=False).status_code == 403


def test_the_session_cookie_is_http_only_and_same_site_strict():
    with gateway() as gw, page(gw) as admin_ui:
        response = httpx.get(admin_ui.base + "/?token=" + admin_ui.token, follow_redirects=False)
        cookie = response.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie


def test_the_page_refuses_another_host_name():
    with gateway() as gw, page(gw) as admin_ui:
        client = admin_ui.session()
        assert client.get("/api/sign-ins", headers={"Host": "evil.example.com:%d" % admin_ui.port}).status_code == 403


def test_actions_need_the_page_origin_and_the_custom_header():
    with gateway() as gw, page(gw) as admin_ui:
        client = admin_ui.session()
        body = {"name": "codex-someone.json"}
        assert client.post("/api/sign-out", json=body).status_code == 403
        assert client.post("/api/sign-out", json=body, headers={"Origin": "https://evil.example.com",
                                                                  "X-CGW-Admin": "1"}).status_code == 403
        assert client.post("/api/sign-out", json=body, headers={"Origin": admin_ui.base}).status_code == 403
        assert gw.upstream.sign_ins != {}
        assert act(client, admin_ui.base, "/api/sign-out", body).status_code == 200
        assert gw.upstream.sign_ins == {}


def test_every_page_response_carries_the_security_headers():
    with gateway() as gw, page(gw) as admin_ui:
        client = admin_ui.session()
        for path in ("/", "/assets/app.js", "/api/sign-ins"):
            headers = client.get(path).headers
            assert "default-src 'none'" in headers["content-security-policy"]
            assert headers["x-frame-options"] == "DENY" and headers["cache-control"] == "no-store"


def test_a_sign_in_from_the_page():
    with gateway() as gw, page(gw, browse=browser()) as admin_ui:
        client = admin_ui.session()
        started = act(client, admin_ui.base, "/api/sign-in", {"provider": "claude"})
        assert started.status_code == 200
        flow = "/api/sign-in/" + started.json()["id"]
        wait_until(lambda: client.get(flow).json()["status"] in ("signed_in", "failed"), timeout=10)
        assert client.get(flow).json()["status"] == "signed_in"
        names = [entry["name"] for entry in client.get("/api/sign-ins").json()]
        assert "anthropic-new.json" in names


def test_the_page_lists_sign_ins_without_tokens():
    with gateway() as gw, page(gw) as admin_ui:
        listed = admin_ui.session().get("/api/sign-ins")
        assert listed.json()[0]["email"] == "someone@example.com"
        assert b"SECRET-ID-TOKEN" not in listed.content
