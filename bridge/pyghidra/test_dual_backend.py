"""Dual-backend comparison tests.

Runs the pyGhidra bridge against a freshly compiled ELF and compares each response with the
reference captured from the Java bridge (Ghidra 12.1.2, same source as test_bridge_protocol's
fixture, `fixtures/java_bridge_*.json`). Addresses and digests depend on the local toolchain, so
the comparison is structural: identical keys, identical value types, canonical address strings.

Run with: REA_TEST_PYGHIDRA=1 GHIDRA_INSTALL_DIR=<ghidra> python3 -m unittest bridge/pyghidra/test_dual_backend.py -v
Set REA_PYGHIDRA_PYTHON to an interpreter that has pyghidra installed (default: this one).
Gate: REA_TEST_PYGHIDRA=1
"""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_bridge_protocol import ENABLED, BridgeProcess, build_fixture

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
CANONICAL_ADDRESS = re.compile(r"^0x[0-9a-f]+$")


def load_reference(operation):
    with open(os.path.join(FIXTURES, f"java_bridge_{operation}.json"), encoding="utf-8") as handle:
        return json.load(handle)


def structural_mismatches(reference, actual, path="$"):
    """Differences in shape between two JSON values; null on either side is an unknown."""
    if reference is None or actual is None:
        return []
    if isinstance(reference, bool) or isinstance(actual, bool):
        return [] if type(reference) is type(actual) else [f"{path}: bool vs non-bool"]
    if isinstance(reference, (int, float)) and isinstance(actual, (int, float)):
        return []
    if type(reference) is not type(actual):
        return [f"{path}: {type(reference).__name__} vs {type(actual).__name__}"]
    if isinstance(reference, dict):
        if set(reference) != set(actual):
            return [f"{path}: keys {sorted(reference)} vs {sorted(actual)}"]
        return [
            mismatch
            for key in reference
            for mismatch in structural_mismatches(reference[key], actual[key], f"{path}.{key}")
        ]
    if isinstance(reference, list):
        if not reference:
            return []
        return [
            mismatch
            for index, item in enumerate(actual)
            for mismatch in _best_match(reference, item, f"{path}[{index}]")
        ]
    if isinstance(reference, str) and CANONICAL_ADDRESS.match(reference):
        return [] if CANONICAL_ADDRESS.match(actual) else [f"{path}: {actual!r} is not canonical"]
    return []


def _best_match(candidates, item, path):
    attempts = [structural_mismatches(candidate, item, path) for candidate in candidates]
    return min(attempts, key=len)


@unittest.skipUnless(ENABLED, "Dual-backend tests require REA_TEST_PYGHIDRA=1")
class TestDualBackend(unittest.TestCase):
    """Compare pyGhidra bridge output against Java bridge reference fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="rea-pyg-dual-")
        cls.target = build_fixture(cls.directory)
        cls.bridge = BridgeProcess(cls.target)
        cls.client = cls.bridge.connect()
        procedures = cls.ask("list_procedures", {"document": None})
        cls.addresses = {item["value"]: item["address"] for item in procedures}

    @classmethod
    def tearDownClass(cls):
        cls.client.request("shutdown")
        cls.bridge.wait_exit()
        cls.client.close()
        cls.bridge.dispose()
        shutil.rmtree(cls.directory, ignore_errors=True)

    @classmethod
    def ask(cls, method, params=None):
        response = cls.client.request(method, params)
        assert response["ok"], response
        return response["result"]

    def assertParity(self, operation, actual):
        reference = load_reference(operation)
        self.assertEqual(structural_mismatches(reference, actual), [], operation)

    def procedure(self, name):
        return {"document": None, "procedure": self.addresses[name]}

    def test_list_procedures_schema_parity(self):
        result = self.ask("list_procedures", {"document": None})
        self.assertParity("list_procedures", result)
        for entry in result:
            self.assertEqual(set(entry), {"address", "value", "procedure"})
            self.assertEqual(set(entry["procedure"]), {"external", "thunk", "thunk_target"})
            if not entry["procedure"]["external"]:
                self.assertRegex(entry["address"], CANONICAL_ADDRESS)

    def test_procedure_pseudo_code_envelope_parity(self):
        result = self.ask("procedure_pseudo_code", self.procedure("add"))
        self.assertParity("procedure_pseudo_code", result)
        self.assertEqual(set(result), {"value", "limitations"})
        self.assertIsInstance(result["value"], str)

    def test_analyze_function_envelope_parity(self):
        result = self.ask("analyze_function", {"procedure": self.addresses["main"]})
        self.assertParity("analyze_function", result)
        self.assertEqual(set(result), set(load_reference("analyze_function")))
        self.assertEqual(result["value"]["procedure"]["name"], "main")

    def test_procedure_callers_and_callees_envelope_parity(self):
        callers = self.ask("procedure_callers", self.procedure("add"))
        callees = self.ask("procedure_callees", self.procedure("main"))
        self.assertParity("procedure_callers", callers)
        self.assertParity("procedure_callees", callees)
        for result in (callers, callees):
            self.assertTrue(all(isinstance(item, str) for item in result["value"]))
        self.assertIn(self.addresses["main"], callers["value"])
        self.assertIn(self.addresses["add"], callees["value"])

    def test_xrefs_parity(self):
        result = self.ask("xrefs", {"document": None, "address": self.addresses["add"]})
        self.assertParity("xrefs", result)

    def test_ping_session_info_parity(self):
        result = self.ask("ping")
        reference = load_reference("ping")
        self.assertEqual(structural_mismatches(reference, result), [])
        self.assertEqual(result["name"], "REA pyGhidra bridge")
        self.assertEqual(set(result["capabilities"]), set(reference["capabilities"]))
        self.assertEqual(result["provider"]["id"], reference["provider"]["id"])

    def test_annotate_mutation_readback(self):
        result = self.ask(
            "annotate_native_function",
            {
                "procedure": self.addresses["scale_by_three"],
                "name": "annotated_scale",
                "comment": "REA plate comment",
                "inline_comment": "REA eol comment",
            },
        )
        self.assertParity("annotate_native_function", result)
        self.assertEqual(set(result), {"annotations", "dossier", "effects"})
        self.assertEqual(result["effects"], load_reference("annotate_native_function")["effects"])
        self.assertEqual(result["dossier"]["procedure"]["name"], "annotated_scale")


class TestStructuralComparison(unittest.TestCase):
    """The comparison itself must reject the regressions it exists to catch."""

    def test_rejects_object_entries_where_addresses_are_expected(self):
        reference = load_reference("procedure_callers")
        broken = {**reference, "value": [{"address": "0x1", "name": "f"}]}
        self.assertNotEqual(structural_mismatches(reference, broken), [])

    def test_rejects_a_missing_envelope_field(self):
        reference = load_reference("procedure_callers")
        self.assertNotEqual(structural_mismatches(reference, {"value": reference["value"]}), [])

    def test_rejects_a_non_canonical_address(self):
        reference = load_reference("procedure_callers")
        self.assertNotEqual(structural_mismatches(reference, {**reference, "value": ["0X401126"]}), [])

    def test_accepts_the_reference_itself(self):
        for operation in ("ping", "list_procedures", "analyze_function", "xrefs"):
            reference = load_reference(operation)
            self.assertEqual(structural_mismatches(reference, reference), [])


if __name__ == "__main__":
    unittest.main()
