"""What the gateway is allowed to carry. Shared by both bridges so they cannot disagree."""

# The only upstream routes. There is no way to name another destination.
ALLOWED_ROUTES = frozenset({("GET", "/v1/models"), ("POST", "/v1/responses")})

# Request headers Codex 0.160.1 sends that upstream needs (recorded in gate 1).
# Everything else, including Authorization and cookies, is dropped.
FORWARDED_REQUEST_HEADERS = frozenset({
    "accept", "content-type", "originator", "user-agent", "session-id", "thread-id",
    "x-client-request-id", "x-codex-beta-features", "x-codex-turn-metadata",
    "x-codex-window-id", "x-openai-internal-codex-responses-lite",
})

# Upstream response headers passed back to Codex.
RETURNED_RESPONSE_HEADERS = frozenset({"content-type"})
