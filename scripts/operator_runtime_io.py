"""Bounded subprocess and Docker ownership primitives for local rehearsals."""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from pathlib import Path

LIMIT = 1024 * 1024
LABEL = "network.iicp.operator-rehearsal"


class RehearsalError(RuntimeError):
    """Content-free failure classification, never a subprocess diagnostic."""


def capture(argv, *, data=None, timeout=60):
    """Drain both pipes without unbounded buffering; terminate on deadline."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    buffers = [bytearray(), bytearray()]
    overflow = [False, False]

    def drain(stream, index):
        with stream:
            while block := stream.read(8192):
                room = LIMIT - len(buffers[index])
                buffers[index].extend(block[:room])
                overflow[index] |= len(block) > room

    readers = [threading.Thread(target=drain, args=(stream, index), daemon=True)
               for index, stream in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    def feed():
        try:
            if data:
                process.stdin.write(data)
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()

    writer = threading.Thread(target=feed, daemon=True)
    try:
        if data and len(data) > LIMIT:
            raise RehearsalError("command_input_limit")
        writer.start()
        process.wait(timeout=timeout)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        if writer.ident is not None:
            writer.join(timeout=5)
        else:
            process.stdin.close()
        for reader in readers:
            reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        raise RehearsalError("command_pipe_not_closed")
    if any(overflow):
        raise RehearsalError("command_output_limit")
    return process.returncode, bytes(buffers[0]), bytes(buffers[1])


def image_reference(value):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:-]*@sha256:[0-9a-f]{64}", value):
        raise RehearsalError("image_digest_required")
    return value


class Docker:
    def __init__(self, run_id, output):
        self.run_id, self.output = run_id, output
        self.events = []
        self.owned = []
        self.secrets = []
        self.log_bytes = 0

    def log(self, raw):
        text = raw.decode("utf-8", "replace")
        for secret in self.secrets:
            text = text.replace(secret, "[REDACTED]")
        text = re.sub(r"mysql://[^\s]+", "mysql://[REDACTED]", text)
        retained = text.encode()[:max(0, 16 * LIMIT - self.log_bytes)]
        with (self.output / "diagnostics.log").open("ab") as stream:
            stream.write(retained)
        self.log_bytes += len(retained)

    def call(self, *args, data=None, timeout=60, allow_failure=False):
        code, out, error = capture(["docker", *args], data=data, timeout=timeout)
        self.log(error)
        if code and not allow_failure:
            raise RehearsalError("docker_command_failed")
        return code, out

    def event(self, step, state, **extra):
        row = {"run_id": self.run_id, "step": step, "state": state, "timestamp": time.time(), **extra}
        self.events.append(row)
        with (self.output / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")

    def create(self, kind, name, args):
        # A failed/timed-out creation may still have created a resource. Track the
        # exclusive name before submission; deletion still requires its label.
        code, _ = self.call(kind, "inspect", name, allow_failure=True)
        if code == 0:
            raise RehearsalError("resource_name_already_exists")
        self.owned.append((kind, name))
        self.call(*args)

    def cleanup(self):
        failures = []
        for kind, name in reversed(self.owned):
            try:
                code, raw = self.call(kind, "inspect", name, allow_failure=True)
                if code:
                    # Inspect failure alone cannot distinguish absent from an
                    # unavailable Docker daemon. Verify against an exact list.
                    _, raw = self.list_named(kind, name)
                    if raw.strip():
                        raise RehearsalError("resource_absence_unverified")
                    continue
                value = json.loads(raw)[0]
                labels = value.get("Config", {}).get("Labels") if kind == "container" else value.get("Labels")
                if (labels or {}).get(LABEL) != self.run_id:
                    raise RehearsalError("resource_ownership_mismatch")
                args = [kind, "rm", "-f", name] if kind == "container" else [kind, "rm", name]
                self.call(*args)
                _, remaining = self.list_named(kind, name)
                if remaining.strip():
                    raise RehearsalError("resource_still_present")
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                failures.append(kind)
        return failures

    def list_named(self, kind, name):
        flags = "-aq" if kind == "container" else "-q"
        return self.call(kind, "ls", flags, "--filter", "name=" + name)

    def failure_evidence(self):
        # Collect before cleanup on success too: boot/schema diagnostics help
        # distinguish a test assertion from a process that never started.
        for kind, name in self.owned:
            if kind != "container":
                continue
            try:
                code, raw = self.call("container", "inspect", name, allow_failure=True)
                if code:
                    continue
                value = json.loads(raw)[0]
                if (value.get("Config", {}).get("Labels") or {}).get(LABEL) != self.run_id:
                    continue
                self.event("container_exit", "OBSERVED", role=name.rsplit("-", 1)[-1],
                           exit_code=value.get("State", {}).get("ExitCode"),
                           running=value.get("State", {}).get("Running"))
                _, output = self.call("logs", "--tail", "1000", name, allow_failure=True)
                self.log(output)
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                self.event("diagnostic_capture", "UNAVAILABLE")
