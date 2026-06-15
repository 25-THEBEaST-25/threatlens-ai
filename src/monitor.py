from __future__ import annotations

import time
from collections import deque
from pathlib import Path
from typing import Iterator


def read_live_log(path: str | Path, max_lines: int = 1000) -> str:
    log_path = Path(path).expanduser()
    if not log_path.exists() or not log_path.is_file():
        return ""

    with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
        return "".join(deque(handle, maxlen=max_lines))


def follow_log(path: str | Path, poll_seconds: float = 2.0, start_at_end: bool = True) -> Iterator[str]:
    log_path = Path(path).expanduser()
    with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
        if start_at_end:
            handle.seek(0, 2)

        while True:
            line = handle.readline()
            if line:
                yield line
                continue
            time.sleep(poll_seconds)
