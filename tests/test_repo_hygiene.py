"""Nothing secret or deployment-specific may be committable.

Scans every file git would track (tracked, staged, or untracked and not ignored) for key
material, tokens, real hostnames, account identifiers, email addresses and home-directory
paths. Documentation uses placeholders; real values live in ~/.cli-gateway/ and in the
hosting platform's service variables.

Run by the pre-commit hook in .githooks/ and as part of the normal test suite.
"""
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
THIS_FILE = Path(__file__).resolve()
SKIPPED_DIRECTORIES = {".git", ".venv", "__pycache__", ".pytest_cache", ".idea", ".vscode"}

# Each pattern is written so that it does not match its own source text.
FORBIDDEN_CONTENT = {
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE" + r" KEY-----"),
    "JSON web token": re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    "API key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "real deployment hostname": re.compile(r"\b[a-z0-9][a-z0-9-]*\.up\.railway\.app\b"),
    "account or resource identifier (UUID)": re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    "home directory path": re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/"),
}
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org")
FORBIDDEN_NAMES = [
    re.compile(pattern) for pattern in (
        r"(^|/)\.env(\..*)?$", r"(^|/)config\.json$", r"\.pem$", r"\.key$", r"_ed25519(\.pub)?$",
        r"(^|/)id_(rsa|ed25519)", r"\.sqlite(-journal)?$", r"(^|/)auth/", r"\.log$", r"\.docx$",
    )
]


def committable_files():
    """Paths git would track: tracked, staged, or untracked and not ignored."""
    try:
        listing = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT, capture_output=True, check=True).stdout
        names = [name for name in listing.decode().split("\0") if name]
    except (OSError, subprocess.CalledProcessError):
        # Not a git checkout (for example an unpacked archive): scan the whole tree.
        names = [str(path.relative_to(ROOT)) for path in ROOT.rglob("*")
                 if path.is_file() and not SKIPPED_DIRECTORIES & set(path.relative_to(ROOT).parts)]
    return sorted(name for name in names if (ROOT / name).is_file())


def text_of(name):
    data = (ROOT / name).read_bytes()
    return None if b"\0" in data else data.decode("utf-8", "replace")


FILES = committable_files()


def test_there_are_files_to_scan():
    assert len(FILES) > 20


@pytest.mark.parametrize("name", FILES)
def test_file_name_is_not_a_secret_or_local_state_file(name):
    assert not any(pattern.search(name) for pattern in FORBIDDEN_NAMES), name


@pytest.mark.parametrize("name", FILES)
def test_file_is_text(name):
    assert text_of(name) is not None, "%s is binary; binary files cannot be reviewed for secrets" % name


@pytest.mark.parametrize("name", FILES)
def test_file_has_no_secret_or_deployment_specific_content(name):
    if (ROOT / name).resolve() == THIS_FILE:
        return
    text = text_of(name) or ""
    found = ["%s: %r" % (label, match.group(0)[:60])
             for label, pattern in FORBIDDEN_CONTENT.items() for match in pattern.finditer(text)]
    found += ["email address: %r" % match.group(0) for match in EMAIL.finditer(text)
              if not match.group(0).lower().endswith(ALLOWED_EMAIL_DOMAINS)]
    assert not found, "%s contains %s" % (name, "; ".join(sorted(set(found))[:5]))


def test_this_machines_real_secrets_are_not_in_any_committable_file():
    """Where a real local config exists, its exact secret values must not appear anywhere."""
    config_path = Path.home() / ".cli-gateway" / "config.json"
    if not config_path.is_file():
        pytest.skip("no local gateway config on this machine")
    config = json.loads(config_path.read_text())
    secrets = [config[field] for field in ("psk", "local_key") if config.get(field)]
    leaks = [name for name in FILES for secret in secrets if secret in (text_of(name) or "")]
    assert not leaks, "real secret values found in: %s" % ", ".join(sorted(set(leaks)))
