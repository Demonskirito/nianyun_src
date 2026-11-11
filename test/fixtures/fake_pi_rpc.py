#!/usr/bin/env python3
"""Minimal Pi RPC stand-in for unit tests (JSONL on stdin/stdout)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> int:
    n = 0
    flag_after = int(os.environ.get("FAKE_PI_FLAG_AFTER") or "0")
    flag_path = os.environ.get("FAKE_PI_FLAG_PATH") or ""
    session_file = os.environ.get("FAKE_PI_SESSION_FILE") or "/tmp/fake-pi-session.jsonl"
    buf = b""
    fd = sys.stdin.fileno()
    while True:
        # os.read on a pipe returns available bytes; BufferedReader.read(n) can
        # block until n bytes or EOF and deadlock the RPC client.
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            if not raw.strip():
                continue
            try:
                cmd = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                emit({"type": "response", "command": "parse", "success": False, "error": "bad json"})
                continue
            if not isinstance(cmd, dict):
                continue
            cid = cmd.get("id")
            typ = cmd.get("type")
            if typ == "prompt":
                n += 1
                emit({"id": cid, "type": "response", "command": "prompt", "success": True})
                emit({"type": "agent_start"})
                emit({"type": "turn_start"})
                emit(
                    {
                        "type": "message_update",
                        "assistantMessageEvent": {"type": "text_delta", "delta": "working"},
                    }
                )
                emit(
                    {
                        "type": "tool_execution_start",
                        "toolCallId": f"t{n}",
                        "toolName": "bash",
                        "args": {"command": "true"},
                    }
                )
                emit(
                    {
                        "type": "tool_execution_end",
                        "toolCallId": f"t{n}",
                        "toolName": "bash",
                        "isError": False,
                        "result": {"content": [{"type": "text", "text": "ok"}]},
                    }
                )
                emit({"type": "message_end", "message": {"role": "assistant"}})
                emit({"type": "turn_end", "message": {}, "toolResults": []})
                emit({"type": "agent_end", "messages": [], "willRetry": False})
                observe_ws = os.environ.get("FAKE_PI_OBSERVE_WS") or ""
                if observe_ws:
                    _write_observe(Path(observe_ws))
                if flag_after and n >= flag_after and flag_path:
                    Path(flag_path).write_text(
                        '[{"flag":"flag{fake}","correct":true,"via":"nianyun-submit"}]\n',
                        encoding="utf-8",
                    )
                emit({"type": "agent_settled"})
            elif typ == "get_session_stats":
                emit(
                    {
                        "id": cid,
                        "type": "response",
                        "command": "get_session_stats",
                        "success": True,
                        "data": {
                            "contextUsage": {
                                "tokens": 210000,
                                "contextWindow": 1000000,
                                "percent": float(os.environ.get("FAKE_PI_CONTEXT_PCT") or "10"),
                            }
                        },
                    }
                )
            elif typ == "get_state":
                emit(
                    {
                        "id": cid,
                        "type": "response",
                        "command": "get_state",
                        "success": True,
                        "data": {
                            "sessionId": "fake-session",
                            "sessionFile": session_file,
                            "isStreaming": False,
                            "messageCount": n,
                        },
                    }
                )
            elif typ == "abort":
                emit({"id": cid, "type": "response", "command": "abort", "success": True})
            else:
                emit(
                    {
                        "id": cid,
                        "type": "response",
                        "command": typ,
                        "success": True,
                    }
                )
    return 0


def _write_observe(ws: Path) -> None:
    tdir = ws / ".nianyun" / "traffic"
    tdir.mkdir(parents=True, exist_ok=True)
    dag = {
        "nodes": [
            {"id": "start", "kind": "start", "label": "入口", "note": "lab"},
            {"id": "recon", "kind": "recon", "label": "表面", "note": "GET / 200"},
            {
                "id": "dir_ssrf",
                "kind": "direction",
                "label": "SSRF",
                "coverage": "inferred-open",
                "note": "import resolver",
            },
        ],
        "edges": [
            {"from": "start", "to": "recon"},
            {"from": "recon", "to": "dir_ssrf"},
        ],
    }
    (tdir / "observe_dag.json").write_text(json.dumps(dag), encoding="utf-8")
    (tdir / "inject.txt").write_text(
        "<nianyun-map>\nHYPOTHESIS: sync resolver\nLOCK:\n- SSRF via import\nANGLES:\n- SSRF\n</nianyun-map>\n",
        encoding="utf-8",
    )
    (tdir / "CONFIRMED.md").write_text("# CONFIRMED\nLOCK: SSRF via import\n", encoding="utf-8")
    (tdir / "map.md").write_text("# map\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
