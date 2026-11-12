"""Pure pilot Junk-digest message candidate; no recipient, transport or I/O.

The caller must separately establish fresh opt-in, fixed source identity and
delivery authority. Rendering a message does not authorize sending it.
"""

from datetime import date, datetime, timedelta, timezone
import re


JST = timezone(timedelta(hours=9))
FIELDS = frozenset({"status", "day", "collected_at", "previous_remaining",
                    "total_remaining", "atomic_snapshot"})
TIMESTAMP = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+09:00\Z")
MAX_COUNT = 2**63 - 1


class InvalidPilotSnapshot(ValueError):
    """Closed error code; never include input values or message data."""


def render_pilot_message(snapshot):
    """Return subject/body only for a strict previous-day fixed-probe result."""
    if type(snapshot) is not dict or set(snapshot) != FIELDS:
        raise InvalidPilotSnapshot("invalid_shape")
    if snapshot["status"] != "ok" or snapshot["atomic_snapshot"] is not False:
        raise InvalidPilotSnapshot("invalid_status")
    day = snapshot["day"]
    stamp = snapshot["collected_at"]
    if type(day) is not str or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day):
        raise InvalidPilotSnapshot("invalid_day")
    if type(stamp) is not str or TIMESTAMP.fullmatch(stamp) is None:
        raise InvalidPilotSnapshot("invalid_time")
    try:
        selected = date.fromisoformat(day)
        observed = datetime.fromisoformat(stamp)
    except ValueError:
        raise InvalidPilotSnapshot("invalid_time") from None
    if (selected.isoformat() != day or observed.utcoffset() != JST.utcoffset(None)
            or observed.date() - timedelta(days=1) != selected
            or observed.hour != 0 or not 5 <= observed.minute < 30):
        raise InvalidPilotSnapshot("invalid_window")
    previous = snapshot["previous_remaining"]
    total = snapshot["total_remaining"]
    if (type(previous) is not int or type(total) is not int
            or not 0 <= previous <= total <= MAX_COUNT):
        raise InvalidPilotSnapshot("invalid_count")
    return {
        "status": "message_candidate",
        "subject": f"Junk日報 {day}",
        "body": (
            f"対象日: {day}（日本時間）\n"
            f"取得時刻: {observed.strftime('%Y-%m-%d %H:%M:%S JST')}\n"
            f"対象日にJunkへ保存され、取得時点でも残るメール: {previous:,}件\n"
            f"Junkフォルダ内の取得時点の総メール数: {total:,}件\n"
            "Junkから削除・移動したメールは含みません。"
            "手動保存分は保存日が対象日の場合に含みます。\n"
        ),
    }
