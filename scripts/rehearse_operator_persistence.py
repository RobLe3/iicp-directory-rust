#!/usr/bin/env python3
"""Execute a verified Linux binary against an owned isolated MySQL database.

This is a project persistence rehearsal, not final qualification, an updater,
production deployment, or cross-SDK conformance. No build/pull is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
import uuid

import prepare_operator_artifact as admission
from operator_directory_outage import Owner
from operator_runtime_io import Docker, LABEL, RehearsalError, image_reference

NODE = "00000000-0000-4000-8000-000000000001"
ROW = (f"INSERT INTO nodes (id,endpoint,region,node_token_hash,max_concurrent,tokens_per_min,status) "
       f"VALUES ('{NODE}','https://provider.invalid','test-region','synthetic-unusable',2,10,'inactive');")
SELECT = "SELECT id,endpoint,region,max_concurrent,tokens_per_min FROM nodes ORDER BY id;"


def output_directory(path):
    path = admission.safe_path(path).resolve()
    if "," in str(path):
        raise RehearsalError("mount_delimiter_in_output_path")
    source = Path(__file__).resolve().parents[1]
    if path == source or source in path.parents or path.exists():
        raise RehearsalError("new_output_outside_source_required")
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise RehearsalError("private_output_parent_required")
    path.mkdir(mode=0o700)
    return path


class Runtime:
    def __init__(self, docker, root, runtime_image, mysql_image, version,
                 sdk_probe_image_ref=None, sdk_probe_image_id=None):
        self.docker, self.root = docker, root
        self.runtime_image, self.mysql_image = runtime_image, mysql_image
        self.version = version
        self.network = docker.run_id + "-net"
        self.db, self.app = docker.run_id + "-db", docker.run_id + "-app"
        self.volume = docker.run_id + "-data"
        self.label = f"{LABEL}={docker.run_id}"
        self.sdk_probe_image_ref = sdk_probe_image_ref
        self.sdk_probe_image_id = sdk_probe_image_id

    def sdk_probe(self):
        """Run prebuilt SDKs in the app namespace while its owned DB is live."""
        if not self.sdk_probe_image_ref:
            return
        d, name = self.docker, self.docker.run_id + "-sdk"
        d.event("sdk_compatibility", "STARTED", image_ref=self.sdk_probe_image_ref,
                image_id=self.sdk_probe_image_id)
        # Track before creating: timeout/interruption still reaches owner cleanup.
        d.create("container", name, ["run", "-d", "--pull=never", "--name", name,
            "--label", self.label, "--network", "container:" + self.app,
            "--memory", "768m", "--cpus", "1", "--pids-limit", "128",
            "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--tmpfs", "/tmp:rw,nosuid,size=64m",
            "--log-opt", "max-size=1m", "--log-opt", "max-file=2",
            "--entrypoint", "python3", self.sdk_probe_image_ref,
            "/probe/scripts/pre1_directory_probe.py", "--directory", "http://127.0.0.1:8090/api", "--directory-outage"])
        # App-side readiness and a newly joined container are different
        # observations. Prove loopback from the probe namespace before the SDK
        # matrix starts so a namespace/startup race is not reported as an SDK
        # semantic failure.
        namespace_preflight = (
            "import time,urllib.request\n"
            "for attempt in range(30):\n"
            " try:\n"
            "  with urllib.request.urlopen('http://127.0.0.1:8090/health',timeout=2) as r:\n"
            "   if r.status == 200: raise SystemExit(0)\n"
            " except Exception:\n"
            "  if attempt == 29: raise\n"
            " time.sleep(1)\n"
            "raise SystemExit(1)\n"
        )
        d.call("exec", name, "python3", "-c", namespace_preflight, timeout=65)
        d.event("sdk_namespace_preflight", "PASS", image_ref=self.sdk_probe_image_ref,
                image_id=self.sdk_probe_image_id)
        controller = Owner(lambda args, timeout: d.call(*args, timeout=timeout)[1],
                           name, self.app, LABEL, d.run_id, self.sdk_probe_image_id)
        owner = None
        owner_error = None
        try:
            try:
                owner = controller.run()
            except Exception as error:
                # A fast probe failure can race the independent outage owner.
                # Capture the bounded probe result before preserving that error.
                owner_error = error
        finally:
            (self.root / "directory-outage-control.json").write_text(json.dumps(controller.snapshot(), sort_keys=True))
        _, status = d.call("wait", name, timeout=1800)
        _, raw = d.call("logs", "--tail", "1000", name)
        # The image validates detailed matrix semantics. Final cross-component
        # acceptance independently revalidates this retained nested evidence.
        if len(raw) > 65536:
            raise RehearsalError("sdk_probe_result_limit")
        (self.root / "sdk-probe.json").write_bytes(raw)
        value = json.loads(raw)
        if owner_error is not None:
            raise owner_error
        if (status.strip() != b"0" or value.get("schema") != "iicp.directory-sdk-probe.v1"
                or value.get("status") != "PASS" or value.get("non_authorizing") is not True
                or type(value.get("qualification_credit")) is not int or value["qualification_credit"] != 0
                or len(value.get("matrix", {}).get("rows", [])) != 18):
            raise RehearsalError("sdk_probe_failed_or_incomplete")
        if value.get("outage_nonce") != owner["nonce"]:
            raise RehearsalError("outage_nonce_differs")
        owner["probe_sha256"] = hashlib.sha256(raw).hexdigest()
        (self.root / "directory-outage.json").write_text(json.dumps(owner, sort_keys=True))
        d.event("sdk_compatibility", "PASS", image_ref=self.sdk_probe_image_ref,
                image_id=self.sdk_probe_image_id,
                result_sha256=hashlib.sha256(raw).hexdigest())

    def start_database(self):
        d = self.docker
        d.create("network", self.network, ["network", "create", "--internal", "--label", self.label, self.network])
        d.create("volume", self.volume, ["volume", "create", "--label", self.label, self.volume])
        password = secrets.token_hex(24)
        d.secrets = [password]
        (self.root / "db.env").write_text(f"MYSQL_ROOT_PASSWORD={password}\nMYSQL_ROOT_HOST=%\nMYSQL_DATABASE=iicp_rehearsal\n")
        (self.root / "app.env").write_text(
            f"DATABASE_URL=mysql://root:{password}@{self.db}:3306/iicp_rehearsal?ssl-mode=DISABLED\n"
            "APP_ENV=testing\nIICP_ALLOW_IN_MEMORY=false\nIICP_OPERATING_MODE=local_only\n"
            "IICP_DIRECTORY_DID=did:web:directory.invalid\n"
            "IICP_DIRECTORY_ENDPOINT=https://directory.invalid\n"
            "IICP_RUNTIME_HEALTH_FILE=/tmp/health.json\nIICP_DB_POOL_ACQUIRE_TIMEOUT_MS=2000\n")
        for name in ("db.env", "app.env"):
            (self.root / name).chmod(0o600)
        d.create("container", self.db, ["run", "-d", "--pull=never", "--name", self.db,
            "--label", self.label, "--network", self.network, "--memory", "2g", "--cpus", "2",
            "--pids-limit", "256", "--log-opt", "max-size=10m", "--log-opt", "max-file=2",
            "--env-file", str(self.root / "db.env"), "--mount", f"type=volume,src={self.volume},dst=/var/lib/mysql",
            self.mysql_image])
        self.wait_database()
        if not self.sql("SELECT VERSION();").strip().startswith(b"8.0."):
            raise RehearsalError("mysql_8_0_required")

    def sql(self, query=None, *, dump=False, database="iicp_rehearsal"):
        # All identifiers and statements are internal constants; credentials stay
        # in the already isolated container environment, not argv or reports.
        command = ('export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; exec mysqldump --single-transaction '
                   '--skip-comments --no-tablespaces iicp_rehearsal' if dump else
                   f'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; exec mysql --batch --skip-column-names {database}')
        return self.docker.call("exec", "-i", self.db, "sh", "-c", command,
                                data=query.encode() if query else None)[1]

    def wait_database(self):
        for _ in range(60):
            try:
                if self.sql("SELECT 1;").strip() == b"1":
                    return
            except RehearsalError:
                pass
            time.sleep(2)
        raise RehearsalError("database_not_ready")

    def start_app(self):
        self.docker.create("container", self.app, ["run", "-d", "--pull=never", "--name", self.app,
            "--label", self.label, "--network", self.network, "--memory", "512m", "--cpus", "1",
            "--pids-limit", "128", "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges",
            "--log-opt", "max-size=10m", "--log-opt", "max-file=2", "--tmpfs", "/tmp:rw,nosuid,size=16m",
            "--user", f"{os.getuid()}:{os.getgid()}", "--env-file", str(self.root / "app.env"),
            "--mount", f"type=bind,src={self.root / 'installed'},dst=/iicp,readonly",
            self.runtime_image, "/iicp/directory"])

    def api(self, path):
        probe = ("import json,urllib.request; "
                 f"r=urllib.request.urlopen('http://127.0.0.1:8090{path}',timeout=3); "
                 "v=r.read(65537); assert len(v)<=65536; print(v.decode())")
        return json.loads(self.docker.call("exec", self.app, "python3", "-c", probe, timeout=10)[1])

    def ready(self):
        for _ in range(60):
            try:
                health = self.api("/health")
            except (RehearsalError, ValueError, subprocess.TimeoutExpired):
                time.sleep(1)
                continue
            # The maintained HTTP identity differs intentionally from package
            # metadata: src/main.rs VERSION is v<CARGO_PKG_VERSION>-rs.
            if not isinstance(health, dict) or health.get("version") != f"v{self.version}-rs":
                raise RehearsalError("runtime_health_version_mismatch")
            if health.get("ok") is True:
                try:
                    # Process health alone does not establish database readiness.
                    self.docker.call("exec", self.app, "/iicp/directory", "db-maintenance-status", "--json")
                    return
                except (RehearsalError, subprocess.TimeoutExpired):
                    pass
            time.sleep(1)
        raise RehearsalError("installed_runtime_not_ready")

    def verify_rows(self, expected):
        current = self.sql(SELECT)
        if not current or current != expected:
            raise RehearsalError("persistent_rows_differ")
        value = self.api("/v1/node/" + NODE)
        if value.get("node_id") != NODE or value.get("region") != "test-region":
            raise RehearsalError("persisted_node_api_differs")
        return hashlib.sha256(current).hexdigest()

    def exercise(self):
        self.docker.event("empty_database_bootstrap", "STARTED")
        self.start_database()
        self.start_app()
        self.ready()
        self.docker.event("empty_database_bootstrap", "PASS")
        self.docker.event("persisted_node_api", "STARTED")
        self.sql(ROW)
        expected = self.sql(SELECT)
        digest = self.verify_rows(expected)
        self.docker.event("persisted_node_api", "PASS", rows_sha256=digest)
        self.docker.event("application_restart", "STARTED")
        self.docker.call("restart", "-t", "0", self.app)
        self.ready()
        self.verify_rows(expected)
        self.docker.event("application_restart", "PASS")
        self.docker.event("database_outage_recovery", "STARTED")
        self.docker.call("stop", "-t", "10", self.db)
        code, _ = self.docker.call("exec", self.app, "/iicp/directory", "db-maintenance-status", "--json",
                                   timeout=45, allow_failure=True)
        if code == 0:
            raise RehearsalError("database_outage_not_reported")
        self.docker.call("start", self.db)
        self.wait_database()
        self.ready()
        self.verify_rows(expected)
        self.docker.event("database_outage_recovery", "PASS")
        self.docker.event("fresh_database_backup_restore", "STARTED")
        self.docker.call("stop", "-t", "10", self.app)
        backup = self.sql(dump=True)
        (self.root / "backup.sql").write_bytes(backup)
        self.sql("CREATE DATABASE iicp_restore;")
        self.sql(backup.decode(), database="iicp_restore")
        restored = self.sql(SELECT, database="iicp_restore")
        if restored != expected:
            raise RehearsalError("restored_rows_differ")
        original_app = self.app
        self.app += "-restore"
        env_file = self.root / "app.env"
        env_file.write_text(env_file.read_text().replace("/iicp_rehearsal?", "/iicp_restore?"))
        self.start_app()
        self.ready()
        self.verify_rows(expected)
        self.docker.call("stop", "-t", "10", self.app)
        self.app = original_app
        self.docker.event("fresh_database_backup_restore", "PASS", backup_sha256=hashlib.sha256(backup).hexdigest())
        if self.sdk_probe_image_ref:
            # Run after persistence comparisons, before destructive schema test.
            # The original container retains its original database environment.
            self.docker.call("start", self.app)
            self.ready()
            self.sdk_probe()
            self.docker.call("stop", "-t", "10", self.app)
        # Mutate only this run's database to prove verify-only startup rejects a
        # partial schema rather than silently falling back to memory or repairing.
        self.docker.event("partial_schema_fail_closed", "STARTED")
        self.sql("ALTER TABLE nodes DROP COLUMN region;")
        self.docker.call("start", self.app)
        _, raw = self.docker.call("wait", self.app, timeout=45)
        if raw.strip() == b"0":
            raise RehearsalError("partial_schema_not_rejected")
        _, output = self.docker.call("logs", "--tail", "1000", self.app)
        # Docker logs splits stderr: the content-free diagnostic is recorded by
        # Docker.call even when stdout is empty. Require the specific cause.
        diagnostics = (self.root / "diagnostics.log").read_bytes() + output
        if b"MySQL schema verification failed" not in diagnostics:
            raise RehearsalError("schema_failure_cause_unverified")
        if self.sql("SHOW COLUMNS FROM nodes LIKE 'region';").strip():
            raise RehearsalError("startup_mutated_existing_schema")
        self.docker.event("partial_schema_fail_closed", "PASS")


def rehearse(args):
    probe_ref = getattr(args, "sdk_probe_image_ref", None)
    probe_id = getattr(args, "sdk_probe_image_id", None)
    expected_ref = ('iicp-pre1-directory-probe:' + probe_id.removeprefix('sha256:')) if probe_id else None
    if bool(probe_ref) != bool(probe_id) or (probe_ref and
            (args.target != "linux-x86_64" or not re.fullmatch(r"sha256:[0-9a-f]{64}", probe_id)
             or probe_ref != expected_ref)):
        raise RehearsalError("sdk_probe_linux_x64_image_id_required")
    for image in (args.runtime_image, args.mysql_image):
        image_reference(image)
    # Verify artifact before creating output or touching Docker.
    identity = admission.prepare(args.fragment, args.fragment_sha256, args.source_commit, args.target)
    root = output_directory(args.output)
    docker = Docker("iicp-rust-ops-" + uuid.uuid4().hex[:16], root)
    result = {"schema": "iicp.directory-rust.persistence-rehearsal.v1", "artifact": identity, "run_id": docker.run_id,
              "status": "FAIL", "qualification_credit": 0, "non_authorizing": True,
              "runtime_image": args.runtime_image, "mysql_image": args.mysql_image,
              "sdk_probe_image_ref": probe_ref, "sdk_probe_image_id": probe_id,
              "sdk_probe_requested": bool(probe_ref),
              "limitations": ["testing environment; no production authority", "no upgrade/rollback or credential recovery",
                              "no cross-SDK conformance or final qualification"]}
    try:
        expected_arch = "amd64" if args.target == "linux-x86_64" else "arm64"
        for image in (args.runtime_image, args.mysql_image, *([probe_ref] if probe_ref else [])):
            _, raw = docker.call("image", "inspect", image)
            inspected = json.loads(raw)[0]
            if inspected.get("Os") != "linux" or inspected.get("Architecture") != expected_arch:
                raise RehearsalError("runtime_image_target_differs")
            if image == probe_ref and inspected.get("Id") != probe_id:
                raise RehearsalError("sdk_probe_image_identity_differs")
        installed = root / "installed"
        installed.mkdir(mode=0o700)
        admission.prepare(args.fragment, args.fragment_sha256, args.source_commit, args.target, installed / "directory")
        Runtime(docker, root, args.runtime_image, args.mysql_image, identity["source_version"],
                probe_ref, probe_id).exercise()
        result["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        result["reason"] = str(error) if isinstance(error, RehearsalError) else type(error).__name__
    finally:
        # A repeated operator interrupt must not skip bounded resource return.
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            try:
                docker.failure_evidence()
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                result["diagnostic_capture"] = "UNAVAILABLE"
            finally:
                failures = docker.cleanup()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        result.update(events=docker.events, cleanup_failures=failures, resources_absent=not failures)
        if failures:
            result["status"] = "FAIL"
        for name in ("db.env", "app.env"):
            (root / name).unlink(missing_ok=True)
        if result["status"] == "PASS":
            (root / "backup.sql").unlink(missing_ok=True)
            (root / "installed/directory").unlink(missing_ok=True)
            (root / "installed").rmdir()
        (root / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        if result["status"] != "PASS":
            docker.console_failure()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fragment", type=Path, required=True)
    parser.add_argument("--fragment-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", choices=sorted(admission.MACHINES), required=True)
    parser.add_argument("--runtime-image", required=True, help="preloaded digest-pinned Python 3/glibc runtime")
    parser.add_argument("--mysql-image", required=True, help="preloaded digest-pinned MySQL 8.0 image")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk-probe-image-ref", help="opt-in deterministic preloaded SDK image reference")
    parser.add_argument("--sdk-probe-image-id", help="expected immutable sha256 image identity")
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result = rehearse(args)
    except (OSError, ValueError, RuntimeError) as error:
        result = {"status": "FAIL", "reason": type(error).__name__, "qualification_credit": 0}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
