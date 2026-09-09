from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

import prepare_operator_artifact as operator_artifact


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_pre1_candidate_artifacts.py"
DOCKERFILE = ROOT / "Dockerfile"


class Pre1CandidateArtifactBuilderTest(unittest.TestCase):
    def test_description_names_primary_and_target_artifacts(self) -> None:
        value = json.loads(
            subprocess.check_output([sys.executable, str(SCRIPT), "--describe"], text=True)
        )
        self.assertEqual(value["component"], "directory-rust")
        self.assertEqual(value["target_artifact"], "release-artifact")
        self.assertEqual(value["portable_artifacts_on"], "linux-x86_64")
        self.assertTrue(value["non_authorizing"])

    def test_fault_injection_fixture_is_not_built_by_the_default_gate(self) -> None:
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        fixture = next(
            row
            for row in manifest["example"]
            if row["name"] == "systemd_watchdog_fixture"
        )
        self.assertEqual(
            fixture["required-features"],
            ["systemd-notify", "runtime-health-fault-injection"],
        )
        self.assertIn("COPY examples ./examples", DOCKERFILE.read_text().splitlines())


class OperatorArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="iicp-operator-artifact-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "directory-binary"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62).to_bytes(2, "little")
        self.binary.write_bytes(header + b"synthetic-not-executable")
        self.binary.chmod(0o600)
        self.commit = "a" * 40
        self.value = {
            "schema": "iicp.pre1-artifact-fragment.v1", "component": "directory-rust",
            "source_commit": self.commit, "source_version": "0.1.15",
            "build_target": "linux-x86_64", "gates": dict(operator_artifact.common.GATES),
            "content_free": True, "secrets_present": False, "non_authorizing": True,
            "artifacts": [operator_artifact.common.artifact("release-artifact", "linux-x86_64", self.binary)],
        }
        self.fragment = self.root / "artifact-fragment.json"
        self.digest = self.save()
        mock = patch.object(operator_artifact.common, "detected_target", return_value="linux-x86_64")
        mock.start()
        self.addCleanup(mock.stop)

    def save(self) -> str:
        self.value["fragment_sha256"] = None
        digest = operator_artifact.common.canonical_sha256(self.value)
        self.value["fragment_sha256"] = digest
        self.fragment.write_text(json.dumps(self.value))
        return digest

    def prepare(self, destination=None):
        return operator_artifact.prepare(self.fragment, self.digest, self.commit,
                                         "linux-x86_64", destination)

    def test_verify_is_read_only_and_not_operational_credit(self) -> None:
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = self.prepare()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertFalse(result["service_started"])
        self.assertFalse(result["operational_tests_run"])
        self.assertEqual(result["qualification_credit"], 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_install_restores_private_executable_copy_without_touching_source(self) -> None:
        destination = self.root / "installed"
        self.assertEqual(self.prepare(destination)["status"], "INSTALLED")
        self.assertEqual(destination.read_bytes(), self.binary.read_bytes())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(self.binary.stat().st_mode), 0o600)

    def test_existing_destination_is_never_overwritten(self) -> None:
        destination = self.root / "installed"
        destination.write_text("preserve me")
        with self.assertRaises(FileExistsError):
            self.prepare(destination)
        self.assertEqual(destination.read_text(), "preserve me")

    def test_symlink_source_parent_and_destination_are_rejected(self) -> None:
        original = self.binary.read_bytes()
        other = self.root / "other"
        other.write_bytes(original)
        self.binary.unlink()
        self.binary.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prepare()
        self.binary.unlink()
        self.binary.write_bytes(original)
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prepare(link / "installed")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.prepare(link)

    def test_shared_writable_install_parent_is_rejected(self) -> None:
        parent = self.root / "shared"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "install parent"):
            self.prepare(parent / "installed")

    def test_wrong_fragment_digest_is_rejected(self) -> None:
        self.value["source_version"] = "0.1.16"
        self.save()
        with self.assertRaisesRegex(ValueError, "fragment digest"):
            self.prepare()

    def test_wrong_source_and_native_target_are_rejected(self) -> None:
        self.commit = "b" * 40
        with self.assertRaisesRegex(ValueError, "identity"):
            self.prepare()
        self.commit = "a" * 40
        with patch.object(operator_artifact.common, "detected_target", return_value="macos-arm64"):
            with self.assertRaisesRegex(ValueError, "native Linux"):
                self.prepare()

    def test_failure_gate_and_authority_flags_are_rejected(self) -> None:
        for name, bad in (("secrets_present", True), ("non_authorizing", False),
                          ("content_free", False), ("component", "client-rust"),
                          ("gates", {**operator_artifact.common.GATES, "locked_build": "FAIL"})):
            previous = self.value[name]
            self.value[name] = bad
            self.digest = self.save()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "identity"):
                self.prepare()
            self.value[name] = previous

    def test_wrong_binary_hash_is_rejected_before_install(self) -> None:
        self.binary.write_bytes(self.binary.read_bytes()[:-1] + b"!")
        with self.assertRaisesRegex(ValueError, "content differs"):
            self.prepare(self.root / "installed")
        self.assertFalse((self.root / "installed").exists())

    def test_copy_failure_removes_only_the_new_partial_destination(self) -> None:
        destination = self.root / "installed"
        original = operator_artifact.inspect_binary

        def fail_copy(stream, row, target, output=None):
            if output is not None:
                output.write(b"partial")
                raise OSError("simulated write failure")
            return original(stream, row, target)

        with patch.object(operator_artifact, "inspect_binary", side_effect=fail_copy):
            with self.assertRaises(OSError):
                self.prepare(destination)
        self.assertFalse(destination.exists())
        self.assertTrue(self.binary.is_file())

    def test_wrong_elf_target_is_rejected_even_when_digest_matches(self) -> None:
        data = bytearray(self.binary.read_bytes())
        data[18:20] = (183).to_bytes(2, "little")
        self.binary.write_bytes(data)
        self.value["artifacts"][0] = operator_artifact.common.artifact("release-artifact", "linux-x86_64", self.binary)
        self.digest = self.save()
        with self.assertRaisesRegex(ValueError, "ELF machine"):
            self.prepare()

    def test_invalid_and_duplicate_binary_records_are_rejected(self) -> None:
        row = dict(self.value["artifacts"][0])
        for rows in ([], [row, row], [{**row, "name": "../outside"}],
                     [{**row, "size_bytes": True}], [{**row, "size_bytes": 2**40}]):
            self.value["artifacts"] = rows
            self.digest = self.save()
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.prepare()

    def test_metadata_is_bounded_and_special_files_cannot_block(self) -> None:
        self.fragment.write_bytes(b" " * (operator_artifact.MAX_FRAGMENT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "metadata bound"):
            self.prepare()
        self.fragment.unlink()
        os.mkfifo(self.fragment)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
