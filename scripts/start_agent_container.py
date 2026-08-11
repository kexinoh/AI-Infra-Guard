#!/usr/bin/env python3
"""Run the API Checker and reconnecting Go agent in one container."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time


CHECKER_PYTHON = "/app/api-checker-venv/bin/python"
AGENT_BINARY = "/app/agent"


def _restart_delay() -> float:
    raw = os.environ.get("AIG_AGENT_RESTART_DELAY_SECONDS", "2")
    try:
        return max(0.5, float(raw))
    except ValueError:
        return 2.0


def _start(command: list[str], name: str) -> subprocess.Popen[bytes]:
    print(f"[agent-container] starting {name}", flush=True)
    return subprocess.Popen(command, start_new_session=True)


def _stop(process: subprocess.Popen[bytes] | None, name: str) -> None:
    if process is None or process.poll() is not None:
        return
    print(f"[agent-container] stopping {name}", flush=True)
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        print(f"[agent-container] force stopping {name}", flush=True)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)


def main() -> int:
    stopping = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        print(f"[agent-container] received signal {signum}", flush=True)
        stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    checker = _start([
        CHECKER_PYTHON,
        "-m",
        "uvicorn",
        "services.api_checker.server:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        "--no-access-log",
    ], "API Checker")
    agent: subprocess.Popen[bytes] | None = None
    next_agent_start = 0.0
    exit_code = 0

    try:
        while not stopping.is_set():
            checker_status = checker.poll()
            if checker_status is not None:
                print(
                    f"[agent-container] API Checker exited with status {checker_status}",
                    file=sys.stderr,
                    flush=True,
                )
                exit_code = checker_status or 1
                break

            if agent is not None:
                agent_status = agent.poll()
                if agent_status is not None:
                    print(
                        f"[agent-container] Agent exited with status {agent_status}; retrying",
                        file=sys.stderr,
                        flush=True,
                    )
                    agent = None
                    next_agent_start = time.monotonic() + _restart_delay()

            if agent is None and time.monotonic() >= next_agent_start:
                agent = _start([AGENT_BINARY], "Agent")

            stopping.wait(0.5)
    finally:
        stopping.set()
        _stop(agent, "Agent")
        _stop(checker, "API Checker")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
