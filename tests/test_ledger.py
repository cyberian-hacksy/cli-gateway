"""Replay ledger: every (kid, rid) is consumed at most once, durably, and it fails closed."""
import sqlite3
import stat
import threading

import pytest

from cgw import ledger

RID = bytes(range(32))
OTHER_RID = bytes(range(1, 33))


@pytest.fixture
def path(tmp_path):
    return tmp_path / "replay.sqlite"


@pytest.fixture
def opened(path):
    ledger.Ledger.create(path)
    book = ledger.Ledger(path)
    yield book
    book.close()


# --- consuming ------------------------------------------------------------------------

def test_first_use_of_a_request_id_is_accepted(opened):
    assert opened.consume("poc-1", RID) is True


def test_second_use_of_the_same_request_id_is_refused(opened):
    opened.consume("poc-1", RID)
    assert opened.consume("poc-1", RID) is False


def test_different_request_ids_are_independent(opened):
    assert opened.consume("poc-1", RID) is True
    assert opened.consume("poc-1", OTHER_RID) is True


def test_same_request_id_under_another_kid_is_independent(opened):
    assert opened.consume("poc-1", RID) is True
    assert opened.consume("poc-2", RID) is True


def test_consumed_id_is_still_refused_after_reopening(path):
    ledger.Ledger.create(path)
    first = ledger.Ledger(path)
    first.consume("poc-1", RID)
    first.close()
    second = ledger.Ledger(path)
    assert second.consume("poc-1", RID) is False
    second.close()


def test_consumed_id_is_visible_to_a_second_connection_before_consume_returns(path, opened):
    opened.consume("poc-1", RID)
    other = sqlite3.connect(path)
    assert other.execute("SELECT COUNT(*) FROM consumed").fetchone()[0] == 1
    other.close()


def test_concurrent_duplicates_are_accepted_exactly_once(opened):
    results, barrier = [], threading.Barrier(16)

    def attempt():
        barrier.wait()
        results.append(opened.consume("poc-1", RID))

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [False] * 15 + [True]


@pytest.mark.parametrize("bad_rid", [b"", bytes(31), bytes(33), "not-bytes"])
def test_request_id_that_is_not_32_bytes_is_an_error(opened, bad_rid):
    with pytest.raises(ledger.LedgerError):
        opened.consume("poc-1", bad_rid)


def test_count_reports_consumed_rows(opened):
    opened.consume("poc-1", RID)
    opened.consume("poc-1", OTHER_RID)
    opened.consume("poc-1", RID)
    assert opened.count() == 2


# --- ceiling --------------------------------------------------------------------------

def test_new_ids_are_refused_at_the_row_ceiling(path):
    ledger.Ledger.create(path)
    book = ledger.Ledger(path, max_rows=2)
    book.consume("poc-1", bytes([1]) * 32)
    book.consume("poc-1", bytes([2]) * 32)
    with pytest.raises(ledger.LedgerFull):
        book.consume("poc-1", bytes([3]) * 32)
    assert book.count() == 2
    book.close()


def test_ledger_full_is_a_ledger_error():
    assert issubclass(ledger.LedgerFull, ledger.LedgerError)


# --- failing closed -------------------------------------------------------------------

def test_opening_a_missing_ledger_fails_and_does_not_create_one(path):
    with pytest.raises(ledger.LedgerError):
        ledger.Ledger(path)
    assert not path.exists()


def test_opening_a_corrupt_file_fails(path):
    path.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(ledger.LedgerError):
        ledger.Ledger(path)


def test_opening_an_unrelated_sqlite_database_fails(path):
    other = sqlite3.connect(path)
    other.execute("CREATE TABLE consumed (kid TEXT, rid BLOB)")
    other.commit()
    other.close()
    with pytest.raises(ledger.LedgerError):
        ledger.Ledger(path)


def test_opening_an_empty_file_fails(path):
    path.write_bytes(b"")
    with pytest.raises(ledger.LedgerError):
        ledger.Ledger(path)


def test_consume_fails_closed_when_the_table_disappears(path, opened):
    other = sqlite3.connect(path)
    other.execute("DROP TABLE consumed")
    other.commit()
    other.close()
    with pytest.raises(ledger.LedgerError):
        opened.consume("poc-1", RID)


def test_consume_after_close_fails(path):
    ledger.Ledger.create(path)
    book = ledger.Ledger(path)
    book.close()
    with pytest.raises(ledger.LedgerError):
        book.consume("poc-1", RID)


# --- explicit creation ----------------------------------------------------------------

def test_create_refuses_to_replace_an_existing_ledger(path):
    ledger.Ledger.create(path)
    with pytest.raises(ledger.LedgerError):
        ledger.Ledger.create(path)


def test_create_makes_missing_parent_directories(tmp_path):
    nested = tmp_path / "bridge" / "replay.sqlite"
    ledger.Ledger.create(nested)
    assert ledger.Ledger(nested).count() == 0


def test_created_ledger_is_owner_only(path):
    ledger.Ledger.create(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
