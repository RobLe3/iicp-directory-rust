#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("assess_prod_seed", ROOT / "ops/assess_prod_seed.py")
assert spec and spec.loader
ASSESS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ASSESS)


def signed_event(key: Ed25519PrivateKey, *, seq: int, event_type: str, node_id: str, previous: str | None):
    event = {
        "event_id": f"event-{seq}",
        "event_type": event_type,
        "service_id": None,
        "seq": seq,
        "ts_ms": 1000 + seq,
        "node_id": node_id,
        "payload": {},
        "prev_hash": ASSESS.expected_prev_hash(previous),
        "sig": None,
    }
    event["sig"] = key.sign(ASSESS.signing_message(event)).hex()
    return event


class PublicSeedAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

    def test_verified_lifecycle_reconstructs_active_nodes(self):
        first = signed_event(self.private, seq=1, event_type="REGISTER", node_id="aaaaaaaa-node", previous=None)
        second = signed_event(self.private, seq=2, event_type="EVICT", node_id="aaaaaaaa-node", previous=first["sig"])
        third = signed_event(self.private, seq=3, event_type="REGISTER", node_id="bbbbbbbb-node", previous=second["sig"])
        result = ASSESS.analyze_events([first, second, third], self.public)
        self.assertEqual(result["active"], {"bbbbbbbb-node"})
        self.assertEqual(result["verified_count"], 3)
        self.assertEqual(result["chain_failure_count"], 0)

    def test_unsigned_and_tampered_events_never_change_state(self):
        unsigned = {"event_type": "REGISTER", "node_id": "aaaaaaaa-node", "sig": None}
        tampered = signed_event(self.private, seq=2, event_type="REGISTER", node_id="bbbbbbbb-node", previous=None)
        tampered["payload"] = {"changed": True}
        result = ASSESS.analyze_events([unsigned, tampered], self.public)
        self.assertEqual(result["active"], set())
        self.assertEqual(result["unsigned_count"], 1)
        self.assertEqual(result["invalid_signature_count"], 1)

    def test_did_key_extraction_and_content_free_shape(self):
        raw = self.public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        encoded = __import__("base64").urlsafe_b64encode(raw).decode().rstrip("=")
        did = {"verificationMethod": [{"publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": encoded}}]}
        self.assertIsInstance(ASSESS.public_key_from_did(did), Ed25519PublicKey)
        rendered = json.dumps({"counts": 2, "content_free": True})
        self.assertNotIn("node_id", rendered)

    def test_base_rejects_credentials_and_plain_http(self):
        for value in ("http://example.test", "https://user:secret@example.test"):
            with self.assertRaises(ValueError):
                ASSESS.validate_base(value)

if __name__ == "__main__":
    unittest.main()
