"""提供可替换的 UTC 时钟。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    """定义服务所需的最小时钟接口。"""

    def now(self) -> datetime:
        """返回带时区的当前时间。"""


class SystemClock:
    """使用系统 UTC 时间。"""

    def now(self) -> datetime:
        """返回当前 UTC 时间。"""

        return datetime.now(timezone.utc)


class FixedClock:
    """为测试与离线验收提供固定时间。"""

    def __init__(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("固定时间必须包含时区")
        self._value = value.astimezone(timezone.utc)

    def now(self) -> datetime:
        """返回固定的 UTC 时间。"""

        return self._value


def parse_timestamp(value: str) -> datetime:
    """解析带时区的 ISO 8601 时间并归一到 UTC。"""

    text = str(value).strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    """格式化为固定宽度、可按字典序比较的 UTC 时间文本。"""

    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
