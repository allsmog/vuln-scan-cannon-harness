"""Claude Code headless CLI wrapper — host edition.

Ported from the defending-code reference harness's `agent.py`, with the
Docker/gVisor layer removed. The reference executes target code, so it wraps
`docker exec <container> claude -p`; cannon's static-review detector only
*reads* source, so we run `claude -p` directly on the host with a read-only
toolset (Read/Grep/Glob). The local `claude` CLI is assumed already
authenticated (you use Claude Code), so no API key is injected here.

Key responsibilities (unchanged from the reference):
  1. run_agent(): async subprocess wrapper around `claude -p`
  2. AgentResult.find_tagged_message(): agents emit structured <tags>, then
     often a short "Done!" — scan backwards for the tags, don't trust the
     last message.
  3. Transcript streaming: per-message JSONL with flush, so a mid-run kill
     leaves a readable transcript on disk.
  4. Resume-on-transient-failure: a dead CLI process (API 5xx, 429, crash)
     is resumed via `--resume <session_id>` with exponential backoff.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# ANSI color — gated on isatty() so piped/redirected output stays clean.
# ──────────────────────────────────────────────────────────────────────────────

_ANSI = {
    "dim": "2;90",
    "red": "91",
    "bold": "1",
    "recon": "96",
    "find": "94",
    "verify": "93",
    "threat": "95",
    "chain": "35",
    "report": "92",
    "cannon": "38;5;208",  # orange — the salvo
}


def color(text: str, name: str, stream=sys.stdout) -> str:
    if not getattr(stream, "isatty", lambda: False)():
        return text
    return f"\033[{_ANSI.get(name, '0')}m{text}\033[0m"


# ──────────────────────────────────────────────────────────────────────────────
# Message → text extraction (stream-json dicts)
# ──────────────────────────────────────────────────────────────────────────────

def _blocks_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b.get("text", "") for b in content
            if isinstance(b, dict) and b.get("type") == "text"
        )
    return ""


def _truncate_tool_results(msg: dict) -> dict:
    """Clip large tool_result content for transcript persistence."""
    if msg.get("type") != "user":
        return msg
    inner = msg.get("message", {})
    content = inner.get("content")
    if not isinstance(content, list):
        return msg
    clipped = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "tool_result":
            c = b.get("content")
            if isinstance(c, str):
                b = {**b, "content": c[:5000]}
            elif isinstance(c, list):
                b = {**b, "content": [
                    ({**x, "text": x.get("text", "")[:5000]} if isinstance(x, dict) else x)
                    for x in c[:10]
                ]}
        clipped.append(b)
    return {**msg, "message": {**inner, "content": clipped}}


def _progress_line(msg: dict, prefix: str) -> None:
    if msg.get("type") != "assistant":
        return
    for b in msg.get("message", {}).get("content", []):
        if not isinstance(b, dict):
            continue
        if b.get("type") == "tool_use":
            inp = b.get("input") or {}
            arg = (inp.get("command") or inp.get("file_path") or inp.get("path")
                   or inp.get("pattern") or "")
            arg = str(arg).replace("\n", " ")[:120]
            print(color(f"{prefix}   → {b.get('name')}: {arg}", "dim", sys.stderr),
                  file=sys.stderr, flush=True)
        elif b.get("type") == "text":
            t = (b.get("text") or "").strip().replace("\n", " ")
            if t:
                print(color(f"{prefix}   · {t[:140]}", "dim", sys.stderr),
                      file=sys.stderr, flush=True)


# ──────────────────────────────────────────────────────────────────────────────
# XML tag parsing — markers in prose, not well-formed XML.
# ──────────────────────────────────────────────────────────────────────────────

def parse_xml_tag(text: str, tag: str) -> str | None:
    """Extract the content of the LAST <tag>...</tag> in text. DOTALL."""
    matches = re.findall(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return matches[-1].strip() if matches else None


def parse_all_tags(text: str, tag: str) -> list[str]:
    """Extract ALL <tag>...</tag> blocks — used for repeated <finding> emissions."""
    return [m.strip() for m in
            re.findall(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)]


# ──────────────────────────────────────────────────────────────────────────────
# AgentResult
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    messages: list[dict] = field(default_factory=list)
    result_message: dict | None = None
    session_id: str | None = None
    error: str | None = None
    resume_count: int = 0

    def find_tagged_message(self, tag: str) -> str:
        """Most-recent assistant message containing <tag>; falls back to last."""
        needle = f"<{tag}>"
        last_assistant = ""
        for msg in reversed(self.messages):
            if msg.get("type") != "assistant":
                continue
            text = _blocks_to_text(msg.get("message", {}).get("content"))
            if not last_assistant:
                last_assistant = text
            if needle in text:
                return text
        return last_assistant

    def all_text(self) -> str:
        """Concatenation of every assistant text block — for harvesting all
        <finding> tags even when they're spread across several messages."""
        return "\n".join(
            _blocks_to_text(m.get("message", {}).get("content"))
            for m in self.messages if m.get("type") == "assistant"
        )

    @property
    def last_assistant_message(self) -> str:
        for msg in reversed(self.messages):
            if msg.get("type") == "assistant":
                return _blocks_to_text(msg.get("message", {}).get("content"))
        return ""

    def transcript(self) -> list[dict]:
        return [_truncate_tool_results(m) for m in self.messages]


# ──────────────────────────────────────────────────────────────────────────────
# The core wrapper
# ──────────────────────────────────────────────────────────────────────────────

# Static review reads source; it never executes the target. A read-only
# toolset is the safety boundary that the reference got from gVisor.
READONLY_TOOLS = ["Read", "Grep", "Glob"]


async def run_agent(
    prompt: str,
    *,
    model: str,
    max_turns: int | None = None,   # accepted for API symmetry; CLI has no turn cap
    max_budget_usd: float | None = None,
    cwd: str | None = None,
    add_dirs: list[str] | None = None,
    tools: list[str] | None = None,
    system_prompt: str | None = None,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    max_resume_attempts: int = 12,
    heartbeat_every: int = 25,
) -> AgentResult:
    """Run a headless `claude -p` session on the host and stream its JSONL.

    `cwd` is the directory the agent runs in (the target source root, so
    Read/Grep/Glob resolve against it). `add_dirs` grants read access to extra
    directories (e.g. the target's context/ docs). `tools` restricts the
    available toolset; defaults to read-only.

    Resilience mirrors the reference: a dead CLI process is resumed up to
    `max_resume_attempts` times with exponential backoff (cap 300s). Partial
    transcripts are always preserved — AgentResult is never lost to an
    exception.
    """
    tool_list = tools if tools is not None else READONLY_TOOLS
    # CLI 2.1.x: --tools is space-variadic (not comma), and there is no
    # --max-turns flag (cost is bounded by --max-budget-usd if needed).
    base_argv = ["claude", "-p", "--verbose",
                 "--output-format", "stream-json",
                 "--permission-mode", "bypassPermissions",
                 "--model", model]
    if tool_list:
        base_argv += ["--tools", *tool_list]
    if max_budget_usd:
        base_argv += ["--max-budget-usd", str(max_budget_usd)]
    for d in (add_dirs or []):
        base_argv += ["--add-dir", d]
    if system_prompt:
        base_argv += ["--append-system-prompt", system_prompt]

    # IS_SANDBOX=1 lets the CLI accept bypassPermissions; CLAUDECODE="" stops
    # the nested-session guard when cannon itself is launched from Claude Code.
    import os
    env = {**os.environ, "IS_SANDBOX": "1", "CLAUDECODE": ""}

    result = AgentResult()
    attempt = 0
    assistant_count = 0
    tool_call_count = 0
    transcript_file = open(transcript_path, "w") if transcript_path else None
    try:
        while True:
            cmd = list(base_argv)
            if attempt > 0 and result.session_id:
                cmd += ["--resume", result.session_id, "continue"]
            else:
                cmd += [prompt]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=16 * 1024 * 1024,
            )
            assert proc.stdout

            try:
                async for raw in proc.stdout:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    result.messages.append(msg)
                    if progress_prefix:
                        _progress_line(msg, progress_prefix)
                    if transcript_file:
                        transcript_file.write(json.dumps(_truncate_tool_results(msg)) + "\n")
                        transcript_file.flush()

                    mtype = msg.get("type")
                    if mtype == "assistant":
                        assistant_count += 1
                        tool_call_count += sum(
                            1 for b in msg.get("message", {}).get("content", [])
                            if isinstance(b, dict) and b.get("type") == "tool_use"
                        )
                        if assistant_count % heartbeat_every == 0:
                            print(f"  [agent] {tool_call_count} tool calls "
                                  f"({assistant_count} msgs)")
                    elif mtype == "system" and msg.get("subtype") == "init":
                        sid = msg.get("session_id")
                        if sid and result.session_id is None:
                            result.session_id = sid
                    elif mtype == "result":
                        result.result_message = msg
                        if msg.get("is_error"):
                            raise RuntimeError(f"CLI result is_error: {msg.get('result')}")
                        if proc.returncode is None:
                            proc.terminate()
                            await proc.wait()
                        return result

                rc = await proc.wait()
                stderr = b""
                if proc.stderr:
                    stderr = await proc.stderr.read()
                raise RuntimeError(
                    f"CLI exited rc={rc} without result: "
                    f"{stderr.decode(errors='replace')[:2000]}"
                )

            except Exception as e:
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
                attempt += 1
                if result.session_id is None or attempt > max_resume_attempts:
                    result.error = f"{type(e).__name__} after {attempt} attempt(s): {e}"
                    return result
                backoff = min(2 ** attempt, 300)
                print(color(
                    f"[agent] {type(e).__name__} on attempt {attempt}, "
                    f"resuming session {result.session_id} in {backoff}s: {e}",
                    "dim", sys.stderr), file=sys.stderr)
                result.resume_count = attempt
                await asyncio.sleep(backoff)
    finally:
        if transcript_file:
            transcript_file.close()
