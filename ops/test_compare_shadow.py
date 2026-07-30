#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("compare_shadow", ROOT / "ops/compare_shadow.py")
assert spec and spec.loader
COMPARE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(COMPARE)


class ShadowComparisonTests(unittest.TestCase):
    def test_public_normalization_retains_schema_not_node_values(self):
        payload = {
            "view": "public",
            "nodes": [{"score": 0.9, "health_label": "healthy"}],
            "relay_available": True,
            "ticketed_dispatch_available": True,
        }
        normalized = COMPARE.normalize_discovery(payload)
        self.assertEqual(normalized["node_count"], 1)
        self.assertEqual(normalized["public_node_fields"], ["health_label", "score"])
        self.assertFalse(normalized["route_fields_present"])
        self.assertNotIn("healthy", str(normalized))

    def test_route_material_anywhere_fails_closed(self):
        payload = {
            "view": "public",
            "nodes": [{"score": 0.9, "transport_metadata": {"tunnel": "secret"}}],
        }
        self.assertTrue(COMPARE.normalize_discovery(payload)["route_fields_present"])

    def test_redaction_descriptor_may_name_omitted_route_fields(self):
        payload = {
            "view": "public",
            "nodes": [{"routing_hint": "https_direct"}],
            "redaction": {"endpoint": "omitted", "node_id": "node_id_prefix_only"},
        }
        self.assertFalse(COMPARE.normalize_discovery(payload)["route_fields_present"])

    def test_semantic_comparison_allows_only_configured_count_delta(self):
        base = {
            "discovery": {
                "view": "public",
                "node_count": 6,
                "route_fields_present": False,
                "public_node_fields": ["score"],
                "relay_available": True,
                "ticketed_dispatch_available": True,
            }
        }
        shadow = {"discovery": dict(base["discovery"], node_count=5)}
        self.assertEqual(
            COMPARE.compare_sample(base, shadow, 0),
            ["public discovery node counts exceed the allowed tolerance"],
        )
        self.assertEqual(COMPARE.compare_sample(base, shadow, 1), [])

    def test_base_url_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            COMPARE.validate_base("https://user:secret@example.test")


if __name__ == "__main__":
    unittest.main()
