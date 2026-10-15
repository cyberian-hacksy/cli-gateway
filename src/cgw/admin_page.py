"""The local sign-in page: manage the gateway's subscription sign-ins from a browser.

It runs on this machine's loopback address only, while `python -m cgw admin` runs, and
holds the decrypted admin key in memory for that long. The page is plain buttons; the
gateway decides what an admin key may do. These checks keep other people and other
websites out of the page itself:

- a one-time link, printed in the terminal, opens a session; the session cookie is
  HttpOnly and SameSite=Strict, so other sites cannot use it;
- every request must name this page's own host (no DNS rebinding);
- every action must come from this page's own origin and carry a custom header, which
  another website cannot send without a CORS preflight this server never approves;
- a strict Content-Security-Policy, no framing, no caching.
"""
import asyncio
import contextlib
import json
import secrets
import uuid

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from cgw import admin

COOKIE = "cgw_admin"
ACTION_HEADER = "x-cgw-admin"
_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app(client, port, token, browse):
    """`client` is an AdminClient, entered for the app's lifetime; `token` the one-time link token;
    `browse(url)` opens a URL in this machine's browser."""
    host = "127.0.0.1:%d" % port
    origin = "http://" + host
    state = {"token": token, "session": None, "flows": {}}

    def secured(response):
        response.headers.update(_SECURITY_HEADERS)
        return response

    def refuse(status, message):
        return secured(JSONResponse({"error": message}, status_code=status))

    def checks(request, action):
        """None when the request may proceed, otherwise the refusal."""
        if request.headers.get("host") != host:
            return refuse(403, "wrong host")
        session = request.cookies.get(COOKIE)
        if not state["session"] or not session or not secrets.compare_digest(session, state["session"]):
            return refuse(403, "no session; open the link printed by: python -m cgw admin")
        if action:
            if request.headers.get("origin") != origin or request.headers.get(ACTION_HEADER) != "1":
                return refuse(403, "actions must come from this page")
        return None

    async def entry(request):
        """The one-time link: trade the token for a session cookie, then load the page."""
        if request.headers.get("host") != host:
            return refuse(403, "wrong host")
        offered = request.query_params.get("token", "")
        if state["token"] and offered and secrets.compare_digest(offered, state["token"]):
            state["token"] = None   # single use
            state["session"] = secrets.token_urlsafe(32)
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(COOKIE, state["session"], httponly=True, samesite="strict", path="/")
            return secured(response)
        refused = checks(request, action=False)
        if refused:
            return refused
        return secured(Response(PAGE, media_type="text/html; charset=utf-8"))

    async def asset(request):
        refused = checks(request, action=False)
        if refused:
            return refused
        name = request.path_params["name"]
        body, media = {"app.js": (SCRIPT, "text/javascript"), "app.css": (STYLE, "text/css")}.get(name, (None, None))
        if body is None:
            return refuse(404, "not found")
        return secured(Response(body, media_type=media + "; charset=utf-8"))

    async def providers(request):
        refused = checks(request, action=False)
        if refused:
            return refused
        return secured(JSONResponse([{"id": key, "name": name} for key, name in admin.PROVIDERS.items()]))

    async def sign_ins(request):
        refused = checks(request, action=False)
        if refused:
            return refused
        try:
            return secured(JSONResponse(await client.sign_ins()))
        except admin.AdminError as error:
            return refuse(502, str(error))

    async def start_sign_in(request):
        refused = checks(request, action=True)
        if refused:
            return refused
        try:
            provider = admin.provider_id(str((await request.json()).get("provider", "")))
        except (ValueError, AttributeError, admin.AdminError) as error:
            return refuse(400, str(error) if isinstance(error, admin.AdminError) else "invalid request")
        flow_id = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        flow = {"provider": provider, "status": "starting", "message": "", "url": None, "paste": loop.create_future()}
        state["flows"][flow_id] = flow

        def opened(url):
            flow["url"], flow["status"] = url, "waiting"
            loop.run_in_executor(None, browse, url)

        async def run():
            try:
                name = await admin.run_sign_in(client, provider, opened, pasted=lambda: flow["paste"],
                                               paste_alongside=True, report=lambda message: None)
                flow["status"], flow["message"] = "signed_in", "%s is signed in" % name
            except admin.AdminError as error:
                flow["status"], flow["message"] = "failed", str(error)
            except Exception:  # never leave a flow hanging on an unexpected error
                flow["status"], flow["message"] = "failed", "the sign-in failed unexpectedly"

        flow["task"] = asyncio.ensure_future(run())
        return secured(JSONResponse({"id": flow_id}))

    async def flow_status(request):
        refused = checks(request, action=False)
        if refused:
            return refused
        flow = state["flows"].get(request.path_params["flow_id"])
        if flow is None:
            return refuse(404, "unknown sign-in")
        return secured(JSONResponse({key: flow[key] for key in ("provider", "status", "message", "url")}))

    async def paste(request):
        refused = checks(request, action=True)
        if refused:
            return refused
        flow = state["flows"].get(request.path_params["flow_id"])
        try:
            redirect = str((await request.json()).get("redirect_url", "")).strip()
        except (ValueError, AttributeError):
            redirect = ""
        if flow is None or not redirect.startswith("http://") or flow["paste"].done():
            return refuse(400, "nothing to hand back")
        flow["paste"].set_result(redirect)
        return secured(JSONResponse({"ok": True}))

    async def sign_out(request):
        refused = checks(request, action=True)
        if refused:
            return refused
        try:
            name = str((await request.json()).get("name", ""))
            await client.sign_out(name)
        except (ValueError, AttributeError):
            return refuse(400, "invalid request")
        except admin.AdminError as error:
            return refuse(502, str(error))
        return secured(JSONResponse({"ok": True}))

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with client:
            yield
        for flow in state["flows"].values():
            task = flow.get("task")
            if task and not task.done():
                task.cancel()

    async def no_icon(request):
        return Response(status_code=204)

    return Starlette(routes=[
        Route("/", entry, methods=["GET"]),
        Route("/favicon.ico", no_icon, methods=["GET"]),
        Route("/assets/{name}", asset, methods=["GET"]),
        Route("/api/providers", providers, methods=["GET"]),
        Route("/api/sign-ins", sign_ins, methods=["GET"]),
        Route("/api/sign-in", start_sign_in, methods=["POST"]),
        Route("/api/sign-in/{flow_id}", flow_status, methods=["GET"]),
        Route("/api/sign-in/{flow_id}/redirect", paste, methods=["POST"]),
        Route("/api/sign-out", sign_out, methods=["POST"]),
    ], lifespan=lifespan)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gateway sign-ins</title>
<link rel="stylesheet" href="/assets/app.css">
<script src="/assets/app.js" defer></script>
</head>
<body>
<main>
  <h1>Gateway sign-ins</h1>
  <p class="lead">Subscriptions the gateway is signed in to. Signing in happens in your browser, on the
  provider's own site; the tokens are created and kept on the gateway, never on this machine.</p>

  <section>
    <h2>Signed in</h2>
    <table id="sign-ins"><thead><tr><th>Provider</th><th>Account</th><th>Status</th><th>File</th><th></th></tr></thead>
    <tbody><tr><td colspan="5" class="muted">Loading…</td></tr></tbody></table>
  </section>

  <section>
    <h2>Sign in to a subscription</h2>
    <div id="providers" class="providers"></div>
    <div id="flow" class="flow" hidden>
      <p id="flow-message"></p>
      <p id="flow-link" hidden>If no tab opened, <a id="flow-url" target="_blank" rel="noopener noreferrer">open the
        sign-in page yourself</a>.</p>
      <details id="flow-paste" hidden>
        <summary>The browser did not come back here?</summary>
        <p>After signing in, the browser lands on an address starting with <code>http://localhost</code>. Paste it:</p>
        <form id="paste-form"><input id="paste-input" type="url" placeholder="http://localhost:…" required>
        <button type="submit">Hand it to the gateway</button></form>
      </details>
    </div>
  </section>
  <p class="muted small">This page works while <code>cgw admin</code> runs in your terminal. Stop it with Ctrl-C.</p>
</main>
</body>
</html>
"""

STYLE = """
:root { --bg: #fafaf9; --fg: #1c1917; --muted: #78716c; --line: #e7e5e4; --accent: #1d4ed8; --ok: #15803d; --bad: #b91c1c; --card: #ffffff; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #1c1917; --fg: #f5f5f4; --muted: #a8a29e; --line: #44403c; --accent: #93c5fd; --ok: #86efac; --bad: #fca5a5; --card: #292524; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, -apple-system, sans-serif; }
main { max-width: 760px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 24px; margin: 0 0 8px; }
h2 { font-size: 16px; margin: 32px 0 12px; }
.lead, .muted { color: var(--muted); }
.small { font-size: 13px; margin-top: 40px; }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
th { font-weight: 600; font-size: 13px; color: var(--muted); }
tr:last-child td { border-bottom: 0; }
.providers { display: flex; flex-wrap: wrap; gap: 8px; }
button { font: inherit; padding: 6px 12px; border-radius: 6px; border: 1px solid var(--line); background: var(--card); color: var(--fg); cursor: pointer; }
button:hover { border-color: var(--accent); }
button.danger { color: var(--bad); }
button:disabled { opacity: .5; cursor: default; }
.flow { margin-top: 16px; padding: 12px 14px; border: 1px solid var(--line); border-radius: 8px; background: var(--card); }
.flow .ok { color: var(--ok); } .flow .bad { color: var(--bad); }
a { color: var(--accent); }
input { font: inherit; width: 100%; padding: 6px 8px; margin: 6px 0; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--fg); }
code { font-size: 13px; }
"""

SCRIPT = r"""
"use strict";
const api = (path, options = {}) => fetch(path, Object.assign({credentials: "same-origin"}, options,
  options.method ? {headers: {"Content-Type": "application/json", "X-CGW-Admin": "1"}} : {}))
  .then(async (response) => {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || ("HTTP " + response.status));
    return body;
  });
const text = (tag, value, className) => { const node = document.createElement(tag); node.textContent = value == null ? "" : String(value); if (className) node.className = className; return node; };
let current = null;

async function loadSignIns() {
  const body = document.querySelector("#sign-ins tbody");
  try {
    const files = await api("/api/sign-ins");
    body.replaceChildren();
    if (!files.length) { const row = document.createElement("tr"); const cell = text("td", "None yet.", "muted"); cell.colSpan = 5; row.append(cell); body.append(row); return; }
    for (const file of files) {
      const row = document.createElement("tr");
      const remove = text("button", "Remove", "danger");
      remove.addEventListener("click", async () => {
        if (remove.dataset.armed !== "1") { remove.dataset.armed = "1"; remove.textContent = "Confirm removal"; return; }
        remove.disabled = true;
        try { await api("/api/sign-out", {method: "POST", body: JSON.stringify({name: file.name})}); } catch (error) { remove.textContent = error.message; return; }
        loadSignIns();
      });
      const action = document.createElement("td"); action.append(remove);
      row.append(text("td", file.provider || file.type), text("td", file.email || file.label || ""),
                 text("td", file.disabled ? "disabled" : (file.status || "")), text("td", file.name), action);
      body.append(row);
    }
  } catch (error) {
    const row = document.createElement("tr"); const cell = text("td", "Could not list sign-ins: " + error.message, "muted"); cell.colSpan = 5; row.append(cell); body.replaceChildren(row);
  }
}

function show(message, className) {
  const node = document.getElementById("flow-message");
  node.textContent = message; node.className = className || "";
  document.getElementById("flow").hidden = false;
}

async function follow(id) {
  while (current === id) {
    let flow;
    try { flow = await api("/api/sign-in/" + id); } catch (error) { show(error.message, "bad"); return; }
    if (flow.url) {
      document.getElementById("flow-url").href = flow.url;
      document.getElementById("flow-link").hidden = false;
      document.getElementById("flow-paste").hidden = false;
    }
    if (flow.status === "signed_in") { show(flow.message, "ok"); document.getElementById("flow-paste").hidden = true; loadSignIns(); return; }
    if (flow.status === "failed") { show(flow.message, "bad"); return; }
    show(flow.status === "starting" ? "Asking the gateway for the sign-in page…" : "Sign in in the browser tab that opened. Waiting…");
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

async function startSignIn(provider, name) {
  document.getElementById("flow-link").hidden = true;
  document.getElementById("flow-paste").hidden = true;
  show("Starting the " + name + " sign-in…");
  try { current = (await api("/api/sign-in", {method: "POST", body: JSON.stringify({provider})})).id; follow(current); }
  catch (error) { show(error.message, "bad"); }
}

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("paste-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try { await api("/api/sign-in/" + current + "/redirect", {method: "POST", body: JSON.stringify({redirect_url: document.getElementById("paste-input").value})}); }
    catch (error) { show(error.message, "bad"); }
  });
  const list = document.getElementById("providers");
  for (const provider of await api("/api/providers")) {
    const button = text("button", provider.name);
    button.addEventListener("click", () => startSignIn(provider.id, provider.name));
    list.append(button);
  }
  loadSignIns();
});
"""
