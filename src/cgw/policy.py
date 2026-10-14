"""What the gateway carries. Shared by both bridges so they cannot disagree.

The routes are CLIProxyAPI's client-facing API for text models, in each format it serves:
OpenAI (chat completions, completions, responses), Anthropic (messages) and Gemini. Any
command-line tool that speaks one of these formats can use the gateway. CLIProxyAPI's
management API, its media, realtime and websocket endpoints, its sign-in callbacks and
everything else stay unreachable: there is no way to name another destination.
"""
import re
from urllib.parse import parse_qsl, urlencode

# A model name in a path: letters, digits and . _ @ + -, starting with a letter or digit.
# No slash, so a path cannot climb out of its route.
_MODEL = r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}"

_ROUTES = (
    # OpenAI format
    ("GET", r"/v1/models"),
    ("GET", r"/v1/models/" + _MODEL),
    ("POST", r"/v1/chat/completions"),
    ("POST", r"/v1/completions"),
    ("POST", r"/v1/responses"),
    ("POST", r"/v1/responses/compact"),
    # Anthropic format
    ("POST", r"/v1/messages"),
    ("POST", r"/v1/messages/count_tokens"),
    # Gemini format: /v1beta/models/<model>:<action>, such as :streamGenerateContent
    ("GET", r"/v1beta/models"),
    ("GET", r"/v1beta/models/" + _MODEL),
    ("POST", r"/v1beta/models/" + _MODEL + r":[A-Za-z]{1,64}"),
    ("POST", r"/v1beta/interactions"),
)
_COMPILED_ROUTES = tuple((method, re.compile(pattern)) for method, pattern in _ROUTES)


def route_allowed(method, path):
    return isinstance(method, str) and isinstance(path, str) and any(
        method == allowed and pattern.fullmatch(path) for allowed, pattern in _COMPILED_ROUTES)


# Query strings are allowed (Gemini streams with ?alt=sse; Claude Code sends ?beta=true),
# within these limits. Credentials in the query are dropped: the gateway uses its own.
MAX_QUERY_CHARS = 1024
_QUERY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_QUERY_VALUE_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f]")
DROPPED_QUERY_PARAMETERS = frozenset({"key", "auth_token"})


def clean_query(raw):
    """The query string to forward, in canonical form and without credentials.

    Raises ValueError if it is malformed or too long. The remote bridge accepts a query only
    if it is already in this form, so both ends forward exactly the same thing.
    """
    if not raw:
        return ""
    if not isinstance(raw, str) or len(raw) > MAX_QUERY_CHARS:
        raise ValueError("query too long")
    kept = []
    for name, value in parse_qsl(raw, keep_blank_values=True, strict_parsing=True):
        if not _QUERY_NAME.fullmatch(name) or _QUERY_VALUE_FORBIDDEN.search(value):
            raise ValueError("invalid query parameter")
        if name.lower() not in DROPPED_QUERY_PARAMETERS:
            kept.append((name, value))
    return urlencode(kept)


# Request headers are forwarded unless they are one of these: credentials (the gateway
# presents its own to CLIProxyAPI), connection and proxy plumbing, browser context, and
# anything addressed to CLIProxyAPI's management API. Every tool sends its own headers, so
# a list of what to keep would have to know every tool; a list of what to drop does not.
_DROPPED_REQUEST_HEADERS = frozenset({
    "authorization", "x-api-key", "x-goog-api-key", "cookie", "x-management-key",
    "host", "content-length", "connection", "keep-alive", "te", "trailer",
    "transfer-encoding", "upgrade", "expect", "accept-encoding",
    "forwarded", "via", "x-real-ip", "true-client-ip", "cf-connecting-ip",
    "origin", "referer",
})
_DROPPED_REQUEST_HEADER_PREFIXES = ("proxy-", "x-forwarded-", "sec-", "cgw-")
MAX_FORWARDED_HEADERS = 64


def header_forwarded(name):
    lowered = name.lower()
    return (lowered not in _DROPPED_REQUEST_HEADERS and "management" not in lowered
            and not lowered.startswith(_DROPPED_REQUEST_HEADER_PREFIXES))


# Upstream response headers passed back to the tool.
RETURNED_RESPONSE_HEADERS = frozenset({"content-type", "retry-after"})
