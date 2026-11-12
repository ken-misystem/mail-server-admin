#!/usr/bin/python3
"""V2 previous-day Junk counter: explicit native flow formatter and space rows.

Fixed account, mailbox and 00:05-00:30 JST execution window. Only aggregate
counts leave this process. Doveadm may update index/cache files.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import re
import select
import subprocess
import sys
import time


ACCOUNT = "ken@mi-sys.jp"
MAILBOX = "Junk"
DOVEADM = "/usr/bin/doveadm"
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
JST = timezone(timedelta(hours=9))
MAX_SMALL_BYTES = 256
MAX_SEARCH_BYTES = 1048576
MAX_SEARCH_ROWS = 20000
SMALL_TIMEOUT = 10
SEARCH_TIMEOUT = 30
STATUS_LINE = re.compile(rb"messages=([0-9]{1,12})\n?\Z", re.ASCII)
SEARCH_LINE = re.compile(rb"[0-9a-fA-F]{32} [1-9][0-9]{0,11}\Z", re.ASCII)


def fixed_command(kind, start=None, end=None):
    if kind == "list" and start is None and end is None:
        return (DOVEADM, "mailbox", "list", "-u", ACCOUNT, MAILBOX)
    if kind == "status" and start is None and end is None:
        return (DOVEADM, "-f", "flow", "mailbox", "status", "-u", ACCOUNT,
                "-t", "messages", MAILBOX)
    if (kind == "search" and type(start) is int and type(end) is int
            and 1000000000 <= start < end <= 9999999999):
        return (DOVEADM, "-f", "flow", "search", "-u", ACCOUNT, "mailbox", MAILBOX,
                "SAVEDSINCE", str(start), "SAVEDBEFORE", str(end))
    raise ValueError("invalid_command")


def fixed_read(command, *, byte_limit, timeout):
    """Bound stdout and time; discard stderr and all partial output."""
    process = None
    result = None
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   shell=False, env=SAFE_ENV, cwd="/", close_fds=True,
                                   bufsize=0)
        fd = process.stdout.fileno()
        os.set_blocking(fd, False)
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ValueError("bounded_read")
            try:
                chunk = os.read(fd, min(4096, byte_limit + 1 - len(data)))
            except BlockingIOError:
                continue
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > byte_limit:
                raise ValueError("bounded_read")
        if process.wait(timeout=max(0, deadline - time.monotonic())) == 0:
            result = bytes(data)
    except (OSError, ValueError, subprocess.SubprocessError):
        result = None
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
            except (OSError, subprocess.SubprocessError):
                result = None
            try:
                process.stdout.close()
            except (OSError, ValueError):
                result = None
    return result


def mailbox_exists(raw):
    return raw == b"Junk\n"


def parse_total(raw):
    if type(raw) is not bytes or len(raw) > MAX_SMALL_BYTES:
        return None
    match = STATUS_LINE.fullmatch(raw)
    return int(match.group(1)) if match else None


def count_search(raw):
    if type(raw) is not bytes or len(raw) > MAX_SEARCH_BYTES:
        return None
    if raw == b"":
        return 0
    if not raw.endswith(b"\n"):
        return None
    rows = raw[:-1].split(b"\n")
    if len(rows) > MAX_SEARCH_ROWS or any(SEARCH_LINE.fullmatch(row) is None for row in rows):
        return None
    if len(set(rows)) != len(rows) or len({row[:32] for row in rows}) != 1:
        return None
    return len(rows)


def window(now):
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("invalid_clock")
    local = now.astimezone(JST)
    if local.hour != 0 or not 5 <= local.minute < 30:
        raise ValueError("outside_daily_window")
    today = local.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday = today - timedelta(days=1)
    start, end = int(yesterday.timestamp()), int(today.timestamp())
    if not 1000000000 <= start < end <= 9999999999:
        raise ValueError("invalid_clock")
    return yesterday.date().isoformat(), start, end


def collect(read=fixed_read, clock=None):
    if clock is None:
        clock = lambda: datetime.now(JST)
    try:
        started = clock()
        day, start, end = window(started)
        listed = read(fixed_command("list"), byte_limit=MAX_SMALL_BYTES,
                      timeout=SMALL_TIMEOUT)
        if not mailbox_exists(listed):
            return {"status": "unavailable", "reason": "mailbox_unverified"}
        first_raw = read(fixed_command("status"), byte_limit=MAX_SMALL_BYTES,
                         timeout=SMALL_TIMEOUT)
        first = parse_total(first_raw)
        if first is None:
            return {"status": "unavailable", "reason": "status_unverified"}
        matches = read(fixed_command("search", start, end),
                       byte_limit=MAX_SEARCH_BYTES, timeout=SEARCH_TIMEOUT)
        count = count_search(matches)
        if count is None:
            return {"status": "unavailable", "reason": "search_unverified"}
        second_raw = read(fixed_command("status"), byte_limit=MAX_SMALL_BYTES,
                          timeout=SMALL_TIMEOUT)
        second = parse_total(second_raw)
        finished = clock()
        if (second is None or finished < started or window(finished)[0] != day
                or second != first or count > second):
            return {"status": "unavailable", "reason": "snapshot_unstable"}
        return {"status": "ok", "day": day,
                "collected_at": finished.astimezone(JST).isoformat(timespec="seconds"),
                "previous_remaining": count, "total_remaining": second,
                "atomic_snapshot": False}
    except Exception:
        return {"status": "unavailable", "reason": "collection_failed"}


def main():
    if len(sys.argv) != 1:
        print('{"status":"denied_arguments"}')
        return 64
    if (sys.platform != "linux" or not sys.flags.isolated or not sys.dont_write_bytecode
            or os.geteuid() != 0):
        print('{"status":"unsupported_execution_context"}')
        return 1
    result = collect()
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
