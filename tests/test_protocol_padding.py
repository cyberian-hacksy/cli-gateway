"""Canonical size buckets preserve arbitrary binary payloads."""
import tracemalloc

import pytest

from cgw import protocol
import wire_reference as ref


@pytest.mark.parametrize("length,want", [(1, 1), (8, 8), (9, 10), (10, 10), (4096, 4096),
                                        (4097, 4352), (65537, 67584)])
def test_padme_known_lengths(length, want):
    assert protocol.padme_size(length) == want


@pytest.mark.parametrize("length,want", [(0, 4096), (4095, 4096), (4096, 4352),
                                        (4 + 8192 + 8 * 1024 * 1024, 8650752)])
def test_request_bucket_includes_marker_and_floor(length, want):
    assert protocol.request_padded_size(length) == want


@pytest.mark.parametrize("payload,want", [(0, 512), (510, 512), (511, 1024), (512, 1024), (16384, 16896)])
def test_response_bucket_includes_type_and_marker(payload, want):
    assert protocol.response_padded_size(payload + 1) == want


@pytest.mark.parametrize("kind", ["request", "response"])
@pytest.mark.parametrize("data", [b"", b"\0", b"\x80", b"x\x80\0\0", bytes(range(256)) * 64,
                                 b"a" * 510, b"a" * 511, b"a" * 512, b"a" * 4095, b"a" * 4096])
def test_padding_round_trips_binary_bytes(kind, data):
    pad, unpad = getattr(protocol, "pad_" + kind), getattr(protocol, "unpad_" + kind)
    padded = pad(data)
    assert padded.startswith(data + b"\x80")
    assert unpad(padded) == data


@pytest.mark.parametrize("kind,size", [("request", 4096), ("response", 512)])
@pytest.mark.parametrize("bad", ["empty", "no_marker", "nonzero_tail", "partial", "extra_bucket"])
def test_noncanonical_padding_is_rejected(kind, size, bad):
    pad, unpad = getattr(protocol, "pad_" + kind), getattr(protocol, "unpad_" + kind)
    padded = pad(b"abc")
    malformed = {"empty": b"", "no_marker": b"\0" * size,
                 "nonzero_tail": padded[:-1] + b"\x01", "partial": padded[:-1],
                 "extra_bucket": padded + b"\0" * size}[bad]
    with pytest.raises(protocol.ProtocolError):
        unpad(malformed)


def test_padme_agrees_with_independent_formula_at_boundaries():
    lengths = set(range(1, 10000))
    for power in range(14, 25):
        lengths.update((2**power - 1, 2**power, 2**power + 1))
    for length in lengths:
        assert protocol.padme_size(length) == ref.padme(length)


@pytest.mark.parametrize("length", [0, -1, True, 1.5])
def test_padme_refuses_invalid_lengths(length):
    with pytest.raises(protocol.ProtocolError):
        protocol.padme_size(length)


def test_removing_padding_from_a_large_request_copies_it_at_most_once():
    padded = protocol.pad_request(b"\x80\x00x" * (3 * 1024 * 1024))
    tracemalloc.start()
    try:
        unpadded = protocol.unpad_request(padded)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert unpadded == b"\x80\x00x" * (3 * 1024 * 1024)
    assert peak < 1.1 * len(padded)

