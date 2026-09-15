"""Limits for the assistant: per-user request rate, one question at a time, and
sanitising the conversation history the browser sends back.

The rate state lives in process memory — correct for the single core worker the
stack runs; a multi-worker deployment would move it to Redis."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque


class ChatLimiter:
    def __init__(self) -> None:
        self._recent: dict[str, deque[float]] = defaultdict(deque)
        self._busy: set[str] = set()
        self._lock = asyncio.Lock()

    async def acquire(self, username: str, per_minute: int, per_day: int) -> str | None:
        """Admit a question, or return why not. Admitted questions must release()."""
        now = time.monotonic()
        async with self._lock:
            if username in self._busy:
                return "one question at a time — wait for the current answer"
            recent = self._recent[username]
            while recent and now - recent[0] > 86400:
                recent.popleft()
            if len(recent) >= per_day:
                return f"daily limit of {per_day} questions reached"
            if sum(1 for t in recent if now - t < 60) >= per_minute:
                return f"limit of {per_minute} questions per minute reached — try again shortly"
            recent.append(now)
            self._busy.add(username)
            return None

    async def release(self, username: str) -> None:
        async with self._lock:
            self._busy.discard(username)


limiter = ChatLimiter()


def clean_history(history: list, max_turns: int, max_chars: int, max_turn_chars: int) -> list[dict]:
    """Keep only plain {role: user|assistant, content: str} turns. Anything else
    the client sends (tool_use / tool_result blocks, system turns) is dropped, so
    a forged history can never inject a fake tool result. Consecutive same-role
    turns are merged, the history starts with a user turn and ends with an
    assistant turn, and it is trimmed from the oldest end to the limits."""
    turns: list[dict] = []
    for t in history[-max_turns:]:
        if not isinstance(t, dict):
            continue
        role, content = t.get("role"), t.get("content")
        if role not in ("user", "assistant") or not isinstance(content, str) or not content.strip():
            continue
        content = content[:max_turn_chars]
        if turns and turns[-1]["role"] == role:
            turns[-1]["content"] = (turns[-1]["content"] + "\n\n" + content)[:max_turn_chars]
        else:
            turns.append({"role": role, "content": content})
    # a trailing user turn never got an answer — the new question replaces it
    while turns and turns[-1]["role"] == "user":
        turns.pop()
    while turns and sum(len(t["content"]) for t in turns) > max_chars:
        turns.pop(0)
    while turns and turns[0]["role"] != "user":
        turns.pop(0)
    return turns
