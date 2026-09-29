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


class QualityWorkflowBoundaryTests(unittest.TestCase):
    def check_changes(self, paths):
        from unittest.mock import patch
        import pre1_harness_binding as binding
        identity = {"harness_source_commit": "1" * 40, "harness_sha256": "sha256:" + "2" * 64}
        with patch.object(binding, "harness_identity", return_value=identity), patch.object(binding, "git", side_effect=[b"", ("\0".join(paths) + "\0").encode()]):
            binding.validate_harness_source(ROOT, "3" * 40, identity)

    def test_reviewed_quality_workflows_are_digest_bound_tooling(self):
        self.check_changes([".github/workflows/quality.yml", ".github/workflows/ci.yml"])

    def test_release_dependencies_and_runtime_remain_frozen(self):
        for path in [".github/workflows/release.yml", ".github/workflows/other.yml", "Cargo.lock", "Cargo.toml", "src/lib.rs"]:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "frozen product source"):
                self.check_changes([path])



# Output handoff regression coverage runs in the existing owning driver gate.
import json
import os
import sys
import tempfile
from unittest.mock import Mock, patch
import pre1_package_execution as adapter


class DirectoryOutputTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((ROOT / 'parity/behavior-contract-v1.json').read_bytes())
        self.context = {'component': module.COMPONENT, 'scenario_id': 'cross-flavor-equivalence', 'mode': 'restricted'}
        self.assertion = module.SCENARIO_CASES['cross-flavor-equivalence']['assertion']
        self.marker = 'IICP_PRE1_DIRECTORY_ASSERTION_PASS ' + self.assertion

    def values(self):
        observations = {}
        for group in ('eligibility_cases', 'ranking_cases', 'pricing_cases'):
            for case in self.contract[group]:
                if group == 'pricing_cases': value = case['expected']
                else:
                    ids = sorted(case['expected_ids']) if group == 'eligibility_cases' else (
                        [] if case['requested_model'] == 'missing-model' else ['fixture-http-ranking'])
                    scores = [0.9 - i / 10 for i in range(len(ids))] if group == 'eligibility_cases' else ([case['expected']] if ids else [])
                    value = {'eligible_ids': ids, 'recommendation_order': ids, 'scores': scores}
                observations[group + '/' + case['name']] = value
        return {row['name']: row['expected'] for row in self.contract['registration_cases']}, {
            'scope': 'installed-' + module.COMPONENT.removeprefix('directory-') + '-tcp-discovery-and-registration-pricing',
            'mode': 'restricted', 'fixture_sha256': 'sha256:61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f',
            'qualification_credit': False, 'production_endpoint_validation': False, 'observations': observations}

    def endpoints(self):
        return {"scope": "installed-" + module.COMPONENT.removeprefix("directory-") + "-tcp-production-endpoints",
            "mode": "restricted", "fixture_sha256": "sha256:61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f",
            "app_env": "production", "qualification_credit": False, "observations": {
                "endpoint_cases/" + row["name"]: {"blocked": row["blocked"], "status": 422,
                    "reason": "IICP-E035" if row["blocked"] else "IICP-E036",
                    "node_rows": 0, "capability_rows": 0, "availability_rows": 0}
                for row in self.contract["endpoint_cases"]}}

    def output(self, registration=None, discovery=None):
        a, b = self.values()
        return '\n'.join(['IICP_PRE1_REGISTRATION_OBSERVATION ' + json.dumps(a if registration is None else registration),
            'IICP_PRE1_REGISTRATION_TRANSPORT tcp',
            'IICP_PRE1_INSTALLED_DISCOVERY_OBSERVATION ' + json.dumps(b if discovery is None else discovery),
            "IICP_PRE1_INSTALLED_ENDPOINT_OBSERVATION " + json.dumps(self.endpoints()), self.marker]) + '\n'

    def test_endpoint_records_fail_closed(self):
        from copy import deepcopy
        original = self.endpoints()
        for field, wrong in (("app_env", "testing"), ("qualification_credit", True),
                             ("mode", "public"), ("fixture_sha256", "sha256:" + "0" * 64)):
            value = deepcopy(original); value[field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                adapter.validate_directory_endpoint_output(value, self.context, self.contract)
        for change in ({"status": 201}, {"blocked": 1}, {"node_rows": False},
                       {"node_rows": 1}, {"reason": "IICP-E035"}):
            value = deepcopy(original)
            value["observations"]["endpoint_cases/public_ipv6"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                adapter.validate_directory_endpoint_output(value, self.context, self.contract)
        value = deepcopy(original); value["observations"].pop("endpoint_cases/public_ipv6")
        with self.assertRaises(ValueError): adapter.validate_directory_endpoint_output(value, self.context, self.contract)

    def test_endpoint_marker_required_and_bounded(self):
        raw = self.output(); line = "IICP_PRE1_INSTALLED_ENDPOINT_OBSERVATION " + json.dumps(self.endpoints())
        for output in (raw.replace(line + "\n", ""), raw.replace(line, line + "\n" + line),
                       raw.replace(line, line.replace('"app_env": "production"', '"app_env": "production", "app_env": "production"'))):
            self.assertEqual(self.code(output), 2)

    def code(self, output, code=0):
        return adapter.directory_output_exit_code(code, output, self.context, self.assertion, ROOT)

    def test_complete_scoped_output_is_accepted(self):
        self.assertEqual(self.code(self.output()), 0)
        self.assertEqual(self.code(self.output(), 101), 101)

    def test_marker_only_other_cases_remain_strict(self):
        context = {**self.context, 'scenario_id': 'credential-missing'}
        self.assertEqual(adapter.directory_output_exit_code(0, self.marker + '\n', context, self.assertion, ROOT), 0)
        self.assertEqual(adapter.directory_output_exit_code(0, self.output(), context, self.assertion, ROOT), 2)
        self.assertEqual(adapter.directory_output_exit_code(0, self.marker + '\nnoise\n', context, self.assertion, ROOT), 2)

    def test_unknown_missing_duplicate_reordered_and_failed_markers_rejected(self):
        raw = self.output(); rows = raw.splitlines()
        for output in (self.marker, raw + self.marker, raw + 'noise\n', '\n'.join(rows[:-1]),
                       '\n'.join([rows[1], rows[0], *rows[2:]]), raw.replace(self.marker, 'FAIL'),
                       raw.replace('TRANSPORT tcp', 'TRANSPORT http-kernel'), 'x' * 1048577):
            with self.subTest(output=output[:70]): self.assertEqual(self.code(output), 2)

    def test_registration_boolean_partial_or_wrong_rollback_rejected(self):
        for field, value in (('node_rows', True), ('node_rows', 2), ('recovered', False)):
            a, b = self.values(); a['recovery_replaces_relations'][field] = value
            self.assertEqual(self.code(self.output(a, b)), 2)
        a, b = self.values(); a['revoked_operator_rolls_back']['capability_rows'] = 1
        self.assertEqual(self.code(self.output(a, b)), 2)

    def test_discovery_identity_coverage_credit_and_transport_scope_rejected(self):
        for field, value in (('mode', 'public'), ('scope', 'other'), ('fixture_sha256', 'sha256:' + 'a' * 64),
                             ('qualification_credit', True), ('production_endpoint_validation', True)):
            a, b = self.values(); b[field] = value
            self.assertEqual(self.code(self.output(a, b)), 2)
        a, b = self.values(); b['observations'].pop(next(iter(b['observations'])))
        self.assertEqual(self.code(self.output(a, b)), 2)

    def test_wrong_pricing_rank_and_eligibility_rejected(self):
        for group in ('pricing_cases', 'ranking_cases', 'eligibility_cases'):
            a, b = self.values(); key = next(k for k in b['observations'] if k.startswith(group))
            if group == 'pricing_cases': b['observations'][key] = True
            elif group == 'ranking_cases': b['observations'][key]['scores'] = [0.111]
            else: b['observations'][key]['eligible_ids'] = []
            self.assertEqual(self.code(self.output(a, b)), 2)

    def test_duplicate_json_nonfinite_and_malformed_rejected(self):
        raw = self.output()
        for output in (raw.replace('"mode": "restricted"', '"mode": "restricted", "mode": "restricted"'),
                       raw.replace('"node_rows": 1', '"node_rows": NaN'),
                       raw.replace('"node_rows": 1', '"node_rows": 1e999'),
                       raw.replace('"node_rows": 1', '"node_rows": invalid')):
            self.assertEqual(self.code(output), 2)

    def test_stale_fixture_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root/'parity').mkdir(); (root/'parity/behavior-contract-v1.json').write_text('{}')
            self.assertEqual(adapter.directory_output_exit_code(0, self.output(), self.context, self.assertion, root), 2)

    def test_main_writes_real_handoff_result_into_existing_proof(self):
        for output, child_code, expected in ((self.output(), 0, 0), (self.marker, 0, 2), (self.output(), 101, 101)):
            component = {'id': module.COMPONENT}; manifest = {'components': [component]}
            proof = {'value': {'fixture': True}, 'artifact': Path('/fixture/artifact')}
            with patch.object(sys, 'argv', ['driver', '--cell', 'fixture', '--scenario', 'cross-flavor-equivalence', '--evidence-mode', 'digest-only']), \
                 patch.dict(os.environ, {'IICP_PRE1_ARTIFACT_ROOT': '/fixture', 'IICP_PRE1_RUN_ID': 'unit-run'}), \
                 patch.object(module, 'validate_context', return_value=('fixture', {}, manifest, self.context)), \
                 patch.object(module, 'validate_runtime'), patch.object(module, 'command_environment', return_value={}), \
                 patch.object(module, 'package_command', return_value=(['fixture'], {}, ROOT, proof)), \
                 patch.object(module.subprocess, 'run', return_value=Mock(returncode=child_code, stdout=output)), \
                 patch.object(module, 'validate_binding'), patch.object(module, 'make_case_proof') as make, \
                 patch.object(module, 'write_case_proof') as write, patch('builtins.print'):
                self.assertEqual(module.main(), expected)
                self.assertEqual(make.call_args.args[3], expected)
                write.assert_called_once_with(make.return_value)



if __name__ == "__main__":
    unittest.main()
