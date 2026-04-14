#!/usr/bin/env python3
"""
penelope_mcp.py — MCP server wrapping penelope for LLM agent shell management.

Solves the stateless-shell problem: each agent tool call can exec into a
persistent reverse-shell session without losing environment, CWD, or state.

Usage (stdio MCP):
    python3 /opt/penelope/penelope_mcp.py

Claude Code ~/.claude/settings.json integration:
    "mcpServers": {
        "penelope": {
            "command": "python3",
            "args": ["/opt/penelope/penelope_mcp.py"]
        }
    }
"""

import os
import sys
import pty
import time
import threading

# ── Patch stdin with a fake PTY so penelope's module-level
#    `TTY_NORMAL = termios.tcgetattr(sys.stdin)` doesn't crash
#    when we're running headless (MCP stdio transport).
_master_fd, _slave_fd = pty.openpty()
_fake_tty = os.fdopen(_slave_fd, "rb+", buffering=0)
_real_stdin  = sys.stdin
_real_stdout = sys.stdout
_real_stderr = sys.stderr

sys.stdin = _fake_tty          # let penelope capture TTY state

sys.path.insert(0, "/opt/penelope")
import penelope as _pen        # initialises options / core / logger globals

sys.stdin  = _real_stdin       # restore real stdio for MCP transport
sys.stdout = _real_stdout
sys.stderr = _real_stderr
_fake_tty.close()
os.close(_master_fd)

# Silence penelope's logging to stdout so it doesn't corrupt the MCP stream
import logging
for handler in _pen.logger.handlers[:]:
    if isinstance(handler, logging.StreamHandler) and handler.stream in (
        sys.__stdout__, sys.__stderr__, _real_stdout, _real_stderr
    ):
        _pen.logger.removeHandler(handler)
_pen.logger.setLevel(logging.WARNING)

# ── MCP server ────────────────────────────────────────────────────────────────
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "penelope",
    instructions=(
        "Persistent reverse-shell manager. "
        "Start a listener, wait for the target to connect, then exec commands "
        "on the session. Sessions survive across tool calls — use session_id to "
        "route commands to the right shell."
    ),
)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _session(session_id: int):
    s = _pen.core.sessions.get(session_id)
    if s is None:
        raise ValueError(f"Session {session_id} not found. Call penelope_sessions() to list active sessions.")
    return s


def _session_info(s) -> dict:
    return {
        "id":       s.id,
        "host":     getattr(s, "hostname", None) or s.ip,
        "ip":       s.ip,
        "port":     s.port,
        "os":       s.OS,
        "type":     s.type,
        "subtype":  s.subtype,
        "user":     getattr(s, "user", None),
        "agent":    s.agent,
        "source":   s.source,   # 'reverse' | 'bind'
    }


# ─── tools ────────────────────────────────────────────────────────────────────

@mcp.tool()
def penelope_listen(port: int = 4444, host: str = "0.0.0.0") -> dict:
    """
    Start a TCP listener waiting for an incoming reverse shell.

    Returns the listener id and the one-liner payloads penelope suggests for
    the target so you can paste them into whatever RCE vector you have.
    """
    listener = _pen.TCPListener(host=host, port=port)
    if not listener:
        return {"ok": False, "error": f"Could not bind {host}:{port}"}

    payloads: list[str] = []
    try:
        raw = str(listener.payloads)         # penelope renders ANSI; strip later
        # strip ANSI escape codes
        import re
        payloads = re.sub(r"\x1b\[[0-9;]*m", "", raw).strip().splitlines()
    except Exception:
        pass

    return {
        "ok":          True,
        "listener_id": listener.id,
        "bind":        f"{host}:{port}",
        "payloads":    payloads,
        "tip":         "Run one of the payloads on the target, then call penelope_sessions() to get the session id.",
    }


@mcp.tool()
def penelope_sessions() -> list[dict]:
    """
    List all active reverse-shell sessions.

    Returns id, host, OS, shell type, and whether the penelope agent is deployed.
    Pass the id to penelope_exec / penelope_upload / penelope_download.
    """
    return [_session_info(s) for s in _pen.core.sessions.values()]


@mcp.tool()
def penelope_wait_session(
    timeout: float = 30.0,
    poll_interval: float = 0.5,
) -> dict:
    """
    Block until at least one new session appears (or timeout expires).

    Useful immediately after triggering a reverse-shell payload — call this
    instead of sleeping and polling manually.

    Args:
        timeout: seconds to wait before giving up
        poll_interval: check interval in seconds
    """
    deadline = time.monotonic() + timeout
    before   = set(_pen.core.sessions.keys())

    while time.monotonic() < deadline:
        new_ids = set(_pen.core.sessions.keys()) - before
        if new_ids:
            new_sessions = [_session_info(_pen.core.sessions[i]) for i in new_ids]
            return {"ok": True, "new_sessions": new_sessions}
        time.sleep(poll_interval)

    return {"ok": False, "error": f"No new session after {timeout}s"}


@mcp.tool()
def penelope_exec(
    session_id: int,
    command: str,
    timeout: float | None = None,
) -> dict:
    """
    Execute a shell command on an active session and return the output.

    The session retains full state (env vars, CWD, running daemons) between
    calls — this is the key advantage over the Bash tool.

    Args:
        session_id: from penelope_sessions()
        command:    shell command to run (bash/sh/cmd/powershell depending on OS)
        timeout:    seconds to wait for output; None uses penelope's default (~10s)
    """
    s = _session(session_id)

    kwargs: dict = {"value": True}
    if timeout is not None:
        kwargs["timeout"] = timeout

    try:
        result = s.exec(command, **kwargs)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    if result is False:
        return {"ok": False, "error": "exec() returned False — session may be dead or no control channel available"}
    if result is None:
        return {"ok": False, "error": "exec() returned None — session not ready (no agent / no pty)"}

    return {"ok": True, "output": result}


@mcp.tool()
def penelope_upload(
    session_id: int,
    local_items: str,
    remote_path: str = "",
) -> dict:
    """
    Upload local file(s)/folder(s) to the remote target.

    Args:
        session_id:  from penelope_sessions()
        local_items: space-separated local paths or URLs to upload
        remote_path: destination path on target; empty → penelope uses session cwd
    """
    s = _session(session_id)
    try:
        kwargs = {"remote_path": remote_path} if remote_path else {}
        ok = s.upload(local_items, **kwargs)
        return {"ok": bool(ok)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool()
def penelope_download(
    session_id: int,
    remote_items: str,
) -> dict:
    """
    Download file(s) from the remote target (saved to penelope's loot directory).

    Args:
        session_id:   from penelope_sessions()
        remote_items: space-separated remote paths to download
    """
    s = _session(session_id)
    try:
        ok = s.download(remote_items)
        return {"ok": bool(ok)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool()
def penelope_kill_session(session_id: int) -> dict:
    """
    Kill a session and close the TCP connection.
    """
    s = _session(session_id)
    try:
        s.kill()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool()
def penelope_stop_listener(listener_id: int) -> dict:
    """
    Stop a TCP listener so it no longer accepts new connections.
    """
    listener = _pen.core.listeners.get(listener_id)
    if listener is None:
        return {"ok": False, "error": f"Listener {listener_id} not found"}
    try:
        listener.stop()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool()
def penelope_listeners() -> list[dict]:
    """
    List active TCP listeners.
    """
    return [
        {
            "id":   lid,
            "bind": f"{l.host}:{l.port}",
        }
        for lid, l in _pen.core.listeners.items()
    ]


@mcp.tool()
def penelope_deploy_agent(session_id: int) -> dict:
    """
    Deploy the penelope Python agent on the target session (Unix only).

    Once the agent is deployed, penelope_exec() uses structured TLV streams
    for reliable stdout/stderr separation and proper exit-code handling,
    rather than the token-bracketing heuristic used on raw shells.

    Recommended: call this once after getting a session, before running commands.
    """
    s = _session(session_id)
    if s.agent:
        return {"ok": True, "note": "Agent already deployed on this session"}
    try:
        ok = s.upgrade()
        return {"ok": bool(ok), "agent": s.agent}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ─── entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Start penelope's core select-loop in a background thread if not already running
    if not _pen.core.started:
        _pen.core.start()

    mcp.run(transport="stdio")
