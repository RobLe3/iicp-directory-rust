#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import copy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pre1_driver", ROOT / "scripts/run_pre1_qualification_case.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)


class DriverContractTests(unittest.TestCase):
    def test_description_is_complete_and_content_free(self) -> None:
        value = module.description()
        self.assertEqual(
            value["schema"], "iicp.pre1-component-driver-description.v1"
        )
        self.assertEqual(value["component"], module.COMPONENT)
        self.assertEqual(value["scenarios"], sorted(module.SCENARIO_COMMANDS))
        self.assertTrue(value["commands_sha256"].startswith("sha256:"))
        self.assertTrue(value["semantic_binding"]["exact_assertion_per_scenario"])
        self.assertTrue(value["semantic_binding"]["exact_assertion_discovery_required"])
        self.assertEqual(
            set(value["semantic_binding"]["cell_dimensions_consumed"]),
            {
                "runtime",
                "target",
                "directory_flavor",
                "mode",
                "cell_id",
                "scenario_id",
            },
        )
        self.assertTrue(value["non_authorizing"])

    def test_cell_parser_rejects_wrong_component_and_boundary(self) -> None:
        good = "|".join(
            (
                module.COMPONENT,
                module.RUNTIMES[0],
                module.TARGETS[0],
                module.DIRECTORIES[0],
                module.MODES[0],
            )
        )
        self.assertEqual(module.parse_cell(good)[0], module.COMPONENT)
        with self.assertRaises(ValueError):
            module.parse_cell("wrong|" + "|".join(good.split("|")[1:]))
        with self.assertRaises(ValueError):
            module.parse_cell(good.replace(module.RUNTIMES[0], "unsupported"))

    def test_referenced_test_files_exist(self) -> None:
        commands = [module.SUPPORT_COMMAND, *module.SCENARIO_COMMANDS.values()]
        for command in commands:
            assertion = command[-3]
            if "--test" in command:
                source = ROOT / "tests" / f"{command[command.index('--test') + 1]}.rs"
            else:
                module_name = assertion.split("::", 1)[0]
                source = (
                    ROOT / "src/main_tests.rs"
                    if module_name == "tests"
                    else ROOT / f"src/{module_name}.rs"
                )
            self.assertTrue(source.is_file(), source)
            self.assertIn(f"fn {assertion.rsplit('::', 1)[-1]}()", source.read_text())
            self.assertEqual(command[-2:], ["--", "--exact"])

    def test_exact_discovery_refuses_zero_or_ambiguous_matches(self) -> None:
        assertion = "module::tests::exact_case"
        self.assertTrue(
            module.exact_assertion_is_listed(f"{assertion}: test\n", assertion)
        )
        self.assertFalse(
            module.exact_assertion_is_listed("0 tests, 0 benchmarks\n", assertion)
        )
        self.assertFalse(
            module.exact_assertion_is_listed(
                f"{assertion}: test\n{assertion}: test\n", assertion
            )
        )

    def test_every_scenario_has_one_unique_exact_assertion(self) -> None:
        self.assertEqual(set(module.SCENARIO_CASES), set(module.SCENARIO_COMMANDS))
        assertions = [row["assertion"] for row in module.SCENARIO_CASES.values()]
        self.assertEqual(len(assertions), len(set(assertions)))
        self.assertNotIn(module.SUPPORT_CASE["assertion"], assertions)

    def test_semantic_context_negative_controls_change_the_binding(self) -> None:
        base = (
            "directory-rust|msrv-1.88|linux-aarch64|rust|restricted",
            "rate-limit",
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
            "sha256:" + "c" * 64,
            "sha256:" + "d" * 64,
        )
        expected = module.canonical_sha256(module.semantic_execution_context(*base))
        mutations = [
            (base[0].replace("msrv-1.88", "rust-1.98.0"), *base[1:]),
            (base[0].replace("linux-aarch64", "linux-x86_64"), *base[1:]),
            (base[0].replace("rust", "php"), *base[1:]),
            (base[0].replace("restricted", "public"), *base[1:]),
            (base[0], "disk-full", *base[2:]),
            (*base[:2], "sha256:" + "e" * 64, *base[3:]),
            (*base[:3], "sha256:" + "e" * 64, *base[4:]),
            (*base[:4], "sha256:" + "e" * 64, base[5]),
            (*base[:5], "sha256:" + "e" * 64),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation[:2]):
                try:
                    observed = module.canonical_sha256(
                        module.semantic_execution_context(*mutation)
                    )
                except ValueError:
                    continue
                self.assertNotEqual(observed, expected)

    def test_environment_manifest_requires_offline_package_smoke_and_digest(self) -> None:
        candidate = "sha256:" + "a" * 64
        artifacts = "sha256:" + "b" * 64
        runtime_map = "sha256:" + "c" * 64
        value = {
            "schema": "iicp.pre1-qualification-environment.v1",
            "status": "READY",
            "target": "linux-aarch64",
            "bindings": {
                "candidate_manifest_sha256": candidate,
                "artifact_materialization_sha256": artifacts,
                "runtime_map_sha256": runtime_map,
                "runner_inventory_sha256": "sha256:" + "d" * 64,
            },
            "network": {},
            "source_state": {},
            "runtimes": {
                "msrv-1.88": {
                    "lock_inputs_sha256": "sha256:" + "e" * 64,
                    "dependency_cache_sha256": "sha256:" + "f" * 64,
                    "online_prepare_status": "PASS",
                    "offline_install_status": "PASS",
                    "package_artifact_smoke_status": "PASS",
                    "egress_disabled_during_offline": True,
                    "empty_volatile_cache_at_start": True,
                }
            },
            "content_free": True,
            "secrets_present": False,
            "non_authorizing": True,
            "environment_sha256": None,
        }
        value["environment_sha256"] = module.canonical_sha256(value)
        self.assertEqual(
            module._validate_environment_manifest(
                value,
                target="linux-aarch64",
                runtime="msrv-1.88",
                candidate_digest=candidate,
                materialization_digest=artifacts,
                runtime_map_digest=runtime_map,
            ),
            value["environment_sha256"],
        )
        for mutation in (
            ("offline_install_status", "FAIL"),
            ("package_artifact_smoke_status", "FAIL"),
            ("egress_disabled_during_offline", False),
        ):
            changed = copy.deepcopy(value)
            changed["runtimes"]["msrv-1.88"][mutation[0]] = mutation[1]
            changed["environment_sha256"] = None
            changed["environment_sha256"] = module.canonical_sha256(changed)
            with self.assertRaises(ValueError):
                module._validate_environment_manifest(
                    changed,
                    target="linux-aarch64",
                    runtime="msrv-1.88",
                    candidate_digest=candidate,
                    materialization_digest=artifacts,
                    runtime_map_digest=runtime_map,
                )

    def test_stable_runtime_is_exactly_bound_to_candidate(self) -> None:
        manifest = {"toolchains": {"rust_stable": "1.98.0"}}
        self.assertEqual(
            module.expected_runtime_version("rust-1.98.0", manifest), "1.98.0"
        )
        manifest["toolchains"]["rust_stable"] = "1.99.0"
        with self.assertRaises(ValueError):
            module.expected_runtime_version("rust-1.98.0", manifest)



class ModernEnvironmentTests(unittest.TestCase):
    def fixture(self):
        runtime = module.RUNTIMES[0]
        value = {
            "schema": "iicp.pre1-qualification-environment.v3",
            "status": "READY", "target": "linux-x86_64",
            "bindings": {key: "sha256:" + char * 64 for key, char in (
                ("candidate_manifest_sha256", "a"),
                ("artifact_materialization_sha256", "b"),
                ("runtime_map_sha256", "c"))},
            "network": {"preparation_egress": "dependency-download-only",
                        "qualification_egress": "disabled", "loopback_fixtures": True},
            "source_state": {"clean_checkout": True, "empty_volatile_caches_at_start": True,
                             "product_artifacts_separate": True},
            "execution": {"execution_kind": "native", "evidence_scope": "functional-and-performance",
                          "host_architecture": "x86_64", "guest_architecture": "x86_64",
                          "container_engine": None, "container_engine_version": None,
                          "emulation_mechanism": None, "image_digest": None},
            "isolation": {"kind": "isolated-fixture", "identity": "test-only",
                          "evidence_sha256": "sha256:" + "d" * 64},
            "runtimes": {runtime: {
                "lock_inputs_sha256": "sha256:" + "e" * 64,
                "dependency_cache_sha256": "sha256:" + "f" * 64,
                "online_prepare_status": "PASS", "offline_install_status": "PASS",
                "package_artifact_smoke_status": "PASS", "egress_disabled_during_offline": True,
                "empty_volatile_cache_at_start": True}},
            "content_free": True, "secrets_present": False, "non_authorizing": True,
            "environment_sha256": None,
        }
        return runtime, value

    def check(self, value, runtime):
        value["environment_sha256"] = None
        value["environment_sha256"] = module.canonical_sha256(value)
        return module._validate_environment_manifest(
            value, target="linux-x86_64", runtime=runtime,
            candidate_digest="sha256:" + "a" * 64,
            materialization_digest="sha256:" + "b" * 64,
            runtime_map_digest="sha256:" + "c" * 64)

    def test_v3_preserves_provenance_and_package_gates(self):
        runtime, value = self.fixture()
        self.assertEqual(self.check(value, runtime), value["environment_sha256"])

    def test_rehashed_invalid_provenance_is_not_accepted(self):
        mutations = [("execution", "guest_architecture", "aarch64"),
                     ("execution", "evidence_scope", "functional-only"),
                     ("execution", "image_digest", "sha256:" + "0" * 64),
                     ("isolation", "evidence_sha256", "invalid"),
                     ("network", "qualification_egress", "enabled"),
                     ("source_state", "product_artifacts_separate", False)]
        for section, key, replacement in mutations:
            runtime, value = self.fixture()
            value[section][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(value, runtime)

    def test_rehashed_invalid_dependency_hash_is_not_accepted(self):
        runtime, value = self.fixture()
        value["runtimes"][runtime]["dependency_cache_sha256"] = "missing"
        with self.assertRaises(ValueError):
            self.check(value, runtime)


if __name__ == "__main__":
    unittest.main()
