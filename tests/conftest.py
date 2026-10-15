"""Shared test settings."""
import nacl.pwhash
import pytest

from cgw import admin


@pytest.fixture(autouse=True)
def cheap_passphrase_hashing(monkeypatch):
    # Argon2id at the real setting takes about two seconds per call; tests use the minimum.
    monkeypatch.setattr(admin, "OPSLIMIT", nacl.pwhash.argon2id.OPSLIMIT_MIN)
    monkeypatch.setattr(admin, "MEMLIMIT", nacl.pwhash.argon2id.MEMLIMIT_MIN)
