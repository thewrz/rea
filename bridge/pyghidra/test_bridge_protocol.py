"""Protocol conformance tests for the pyGhidra bridge.

These tests launch the real bridge against a freshly compiled ELF, so they need Ghidra and
pyGhidra installed.
Run with: REA_TEST_PYGHIDRA=1 GHIDRA_INSTALL_DIR=<ghidra> python3 -m unittest bridge/pyghidra/test_bridge_protocol.py -v
Set REA_PYGHIDRA_PYTHON to an interpreter that has pyghidra installed (default: this one).
Gate: REA_TEST_PYGHIDRA=1
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ENABLED = os.environ.get("REA_TEST_PYGHIDRA") == "1"
BRIDGE_MAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "__main__.py")
TOKEN = "t" * 32
STARTUP_TIMEOUT_SECONDS = 600
FIXTURE_SOURCE = """
#include <stdio.h>
#include <string.h>
static const char *greeting = "hello rea pyghidra";
int add(int a, int b) { return a + b; }
int main(int argc, char **argv) {
  printf("%s %d\\n", greeting, add(argc, 2));
  return (int)strlen(greeting);
}
"""
GREETING = b"hello rea pyghidra"
INVENTORY_METHODS = {
    "read_binary_inventory_summary", "inspect_native_load_image", "read_bytes", "search_bytes",
    "address_to_file_offset", "address_name", "list_documents", "list_names", "list_procedures",
    "list_segments", "list_strings", "procedure_address", "resolve_containing_procedure",
    "search_procedures", "search_strings", "set_address_name", "set_addresses_names",
}


def build_fixture(directory):
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a C compiler (cc) is required to build the test fixture")
    source = os.path.join(directory, "fixture.c")
    binary = os.path.join(directory, "fixture")
    with open(source, "w", encoding="utf-8") as handle:
        handle.write(FIXTURE_SOURCE)
    subprocess.run([compiler, "-O0", "-no-pie", "-o", binary, source], check=True)
    return binary


def ghidra_version(install_dir):
    properties = os.path.join(install_dir, "Ghidra", "application.properties")
    with open(properties, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError(f"no application.version in {properties}")


def sha256_of(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class BridgeClient:
    def __init__(self, endpoint):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(endpoint)
        self.reader = self.sock.makefile("rb")
        self.next_id = 0

    def send_raw(self, data):
        self.sock.sendall(data)

    def read_response(self):
        line = self.reader.readline()
        return json.loads(line) if line else None

    def request(self, method, params=None, token=TOKEN):
        self.next_id += 1
        frame = {"id": self.next_id, "token": token, "method": method, "params": params or {}}
        self.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        response = self.read_response()
        assert response is not None and response["id"] == self.next_id
        return response

    def close(self):
        self.reader.close()
        self.sock.close()


class BridgeProcess:
    """One bridge subprocess with its own runtime root, as the launcher would create it."""

    def __init__(self, target, **descriptor_overrides):
        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if not install_dir:
            raise RuntimeError("GHIDRA_INSTALL_DIR must name a Ghidra installation")
        self.target = target
        self.root = tempfile.mkdtemp(prefix="rea-pyg-")
        self.endpoint = os.path.join(self.root, "bridge.sock")
        self.descriptor_path = os.path.join(self.root, "session.json")
        self.stderr_path = os.path.join(self.root, "stderr.log")
        descriptor = {
            "transport": "unix-socket",
            "endpoint_path": self.endpoint,
            "token": TOKEN,
            "run_id": str(uuid.uuid4()),
            "target_sha256": sha256_of(target),
            "provider_version": ghidra_version(install_dir),
            "profile_digest": "a" * 64,
            **descriptor_overrides,
        }
        with open(self.descriptor_path, "w", encoding="utf-8") as handle:
            json.dump(descriptor, handle)
        self.descriptor = descriptor
        interpreter = os.environ.get("REA_PYGHIDRA_PYTHON", sys.executable)
        with open(self.stderr_path, "w", encoding="utf-8") as stderr:
            self.process = subprocess.Popen(
                [interpreter, BRIDGE_MAIN, self.descriptor_path, target],
                stderr=stderr,
                env={**os.environ, "GHIDRA_INSTALL_DIR": install_dir},
            )

    def log(self):
        with open(self.stderr_path, encoding="utf-8") as handle:
            return handle.read()

    def wait_for_socket(self):
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while not os.path.exists(self.endpoint):
            if self.process.poll() is not None:
                raise RuntimeError(f"bridge exited {self.process.returncode}:\n{self.log()[-4000:]}")
            if time.monotonic() > deadline:
                raise TimeoutError(f"bridge socket never appeared:\n{self.log()[-4000:]}")
            time.sleep(0.2)

    def connect(self):
        self.wait_for_socket()
        return BridgeClient(self.endpoint)

    def wait_exit(self, timeout=120):
        return self.process.wait(timeout=timeout)

    def dispose(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        shutil.rmtree(self.root, ignore_errors=True)


@unittest.skipUnless(ENABLED, "pyGhidra tests require REA_TEST_PYGHIDRA=1")
class TestBridgeProtocol(unittest.TestCase):
    """Every test shares one analyzed bridge; mutating tests use addresses no other test reads."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="rea-pyg-fixture-")
        cls.target = build_fixture(cls.directory)
        cls.bridge = BridgeProcess(cls.target)
        cls.client = cls.bridge.connect()
        procedures = cls.client.request("list_procedures", {"document": None})["result"]
        cls.main_address = next(item["address"] for item in procedures if item["value"] == "main")
        cls.add_address = next(item["address"] for item in procedures if item["value"] == "add")
        strings = cls.client.request("list_strings", {"document": None, "address": None})["result"]
        cls.greeting_address = next(
            item["address"] for item in strings if item["value"] == GREETING.decode()
        )

    @classmethod
    def tearDownClass(cls):
        cls.client.request("shutdown")
        cls.bridge.wait_exit()
        cls.client.close()
        cls.bridge.dispose()
        shutil.rmtree(cls.directory, ignore_errors=True)

    def ask(self, method, params=None):
        response = self.client.request(method, params)
        self.assertTrue(response["ok"], response)
        return response["result"]

    def ask_failure(self, method, params, code):
        response = self.client.request(method, params)
        self.assertFalse(response["ok"], response)
        self.assertEqual(response["error"]["code"], code, response)
        return response["error"]["message"]

    def test_ping_response_shape(self):
        result = self.ask("ping")
        self.assertEqual(result["name"], "REA pyGhidra bridge")
        self.assertEqual(result["run_id"], self.bridge.descriptor["run_id"])
        self.assertEqual(result["profile_digest"], "a" * 64)
        self.assertEqual(result["provider"]["id"], "ghidra")
        self.assertFalse(result["read_only"])
        self.assertTrue(result["analysis_complete"])
        self.assertFalse(result["analysis_timed_out"])
        for key in ("name", "language_id", "compiler_spec_id", "image_base",
                    "default_address_space", "sha256"):
            self.assertIn(key, result["target"])
        self.assertEqual(result["target"]["sha256"], sha256_of(self.target))
        self.assertRegex(result["target"]["image_base"], r"^0x[0-9a-f]+$")

    def test_ping_advertises_exactly_the_registered_methods(self):
        capabilities = self.ask("ping")["capabilities"]
        self.assertEqual(len(capabilities), len(set(capabilities)))
        self.assertEqual(set(capabilities), INVENTORY_METHODS | {"ping", "shutdown"})

    def test_wrong_token_is_refused_and_the_session_continues(self):
        refused = self.client.request("ping", token="x" * 32)
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["error"]["code"], "invalid_request")
        self.assertNotIn("token", json.dumps(refused))
        self.assertTrue(self.client.request("ping")["ok"])

    def test_unknown_method_and_extra_fields_are_rejected(self):
        self.ask_failure("no_such_method", {}, "method_unavailable")
        self.ask_failure("list_documents", {"extra": 1}, "invalid_request")
        self.ask_failure("read_bytes", {"document": "other", "address": "0x0", "length": 1}, "not_found")

    def test_list_documents_names_the_program(self):
        self.assertEqual(self.ask("list_documents"), [self.ask("ping")["target"]["name"]])

    def test_list_procedures_response_shape(self):
        result = self.ask("list_procedures", {"document": None})
        self.assertTrue(result)
        for entry in result:
            self.assertEqual(set(entry), {"address", "value", "procedure"})
            self.assertEqual(set(entry["procedure"]), {"external", "thunk", "thunk_target"})
        main = next(entry for entry in result if entry["value"] == "main")
        self.assertFalse(main["procedure"]["external"])
        self.assertTrue(any(entry["procedure"]["external"] for entry in result))
        addresses = [entry["address"] for entry in result if not entry["procedure"]["external"]]
        self.assertEqual(addresses, sorted(addresses, key=lambda text: int(text, 16)))

    def test_list_segments_response_shape(self):
        result = self.ask("list_segments", {"document": None})
        text = next(block for block in result if block["name"] == ".text")
        self.assertTrue(text["executable"])
        self.assertFalse(text["writable"])
        self.assertEqual(text["permissions"], {"available": True, "source": "ghidra-memory-block"})
        self.assertEqual(text["provenance"], "ghidra-memory-block")
        self.assertEqual(text["sections"], [])
        self.assertGreater(int(text["end"], 16), int(text["start"], 16))

    def test_list_strings_nests_string_facts(self):
        result = self.ask("list_strings", {"document": None, "address": None})
        entry = next(item for item in result if item["value"] == GREETING.decode())
        self.assertEqual(set(entry["string"]), {"encoding", "termination", "byte_length"})
        self.assertEqual(entry["string"]["byte_length"], len(GREETING) + 1)
        self.assertEqual(entry["string"]["termination"], "present_or_not_required")
        filtered = self.ask("list_strings", {"document": None, "address": self.greeting_address})
        self.assertEqual([item["value"] for item in filtered], [GREETING.decode()])

    def test_inventory_summary_counts_match_the_listings(self):
        summary = self.ask("read_binary_inventory_summary")
        self.assertEqual(summary["segments"], self.ask("list_segments", {"document": None}))
        self.assertEqual(
            summary["procedure_count"], len(self.ask("list_procedures", {"document": None}))
        )
        self.assertEqual(
            summary["string_count"],
            len(self.ask("list_strings", {"document": None, "address": None})),
        )

    def test_read_bytes_reports_completeness(self):
        result = self.ask(
            "read_bytes", {"document": None, "address": self.greeting_address, "length": len(GREETING)}
        )
        self.assertEqual(bytes.fromhex(result["bytes_hex"]), GREETING)
        self.assertEqual(result["returned_bytes"] * 2, len(result["bytes_hex"]))
        self.assertTrue(result["complete"])
        oversized = self.ask(
            "read_bytes", {"document": None, "address": self.greeting_address, "length": 1 << 40}
        )
        self.assertFalse(oversized["complete"])
        self.assertEqual(oversized["returned_bytes"] * 2, len(oversized["bytes_hex"]))
        self.assertLess(oversized["returned_bytes"], oversized["requested_bytes"])
        unmapped = self.ask("read_bytes", {"document": None, "address": "0xdeadbeef00", "length": 4})
        self.assertEqual((unmapped["returned_bytes"], unmapped["complete"]), (0, False))
        self.ask_failure("read_bytes", {"document": None, "address": "0x0", "length": 0}, "invalid_request")

    def test_search_bytes_finds_the_string_and_pages_by_cursor(self):
        pattern = GREETING[:5].hex()
        found = self.ask("search_bytes", {"document": None, "pattern": pattern, "limit": 100})
        self.assertEqual([match["address"] for match in found["matches"]], [self.greeting_address])
        self.assertTrue(found["complete"])
        self.assertIsNone(found["next_cursor"])
        self.assertEqual(
            found["searched"]["bytes"], sum(block["bytes"] for block in found["searched"]["blocks"])
        )
        everywhere = self.ask("search_bytes", {"document": None, "pattern": "6c", "limit": 1000})
        pages, cursor = [], None
        while True:
            params = {"document": None, "pattern": "6c", "limit": 3}
            if cursor is not None:
                params["cursor"] = cursor
            page = self.ask("search_bytes", params)
            pages += [match["address"] for match in page["matches"]]
            self.assertEqual(page["complete"], page["next_cursor"] is None)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        self.assertEqual(pages, [match["address"] for match in everywhere["matches"]])
        self.assertGreater(len(pages), 3)

    def test_search_bytes_cursor_is_bound_to_its_query(self):
        page = self.ask("search_bytes", {"document": None, "pattern": "6c", "limit": 1})
        self.assertIsNotNone(page["next_cursor"])
        self.ask_failure(
            "search_bytes",
            {"document": None, "pattern": "6d", "limit": 1, "cursor": page["next_cursor"]},
            "invalid_request",
        )

    def test_search_bytes_wildcards_masks_and_bounds(self):
        wildcard = self.ask("search_bytes", {"document": None, "pattern": "6c ?? 6f", "limit": 10})
        self.assertEqual(len(wildcard["matches"]), 1)
        masked = self.ask(
            "search_bytes", {"document": None, "pattern": "6c", "mask": "ff", "limit": 1000}
        )
        self.assertTrue(masked["matches"])
        bounded = self.ask(
            "search_bytes",
            {"document": None, "pattern": "6c", "start": self.greeting_address,
             "end": self.greeting_address, "limit": 10},
        )
        self.assertEqual(bounded["matches"], [])
        self.ask_failure("search_bytes", {"document": None, "pattern": "??", "limit": 1}, "invalid_request")

    def test_address_to_file_offset_matches_the_target_file(self):
        result = self.ask("address_to_file_offset", {"document": None, "address": self.greeting_address})
        with open(self.target, "rb") as handle:
            handle.seek(result["file_offset"])
            self.assertEqual(handle.read(len(GREETING)), GREETING)
        self.ask_failure("address_to_file_offset", {"document": None, "address": "0xdeadbeef00"}, "invalid_request")

    def test_non_default_address_spaces_round_trip(self):
        names = self.ask("list_names", {"document": None, "address": None})
        external = next(item for item in names if item["address"].startswith("EXTERNAL:0x"))
        again = self.ask("list_names", {"document": None, "address": external["address"]})
        self.assertIn(external["value"], [item["value"] for item in again])
        self.ask_failure("list_names", {"document": None, "address": "NOSPACE:0x1"}, "invalid_request")

    def test_resolve_containing_procedure(self):
        inside = hex(int(self.main_address, 16) + 4)
        found = self.ask("resolve_containing_procedure", {"document": None, "address": inside})
        self.assertTrue(found["found"])
        self.assertEqual(found["procedure"]["address"], self.main_address)
        self.assertEqual(found["procedure"]["classification"]["provenance"], "ghidra-function-manager")
        self.assertTrue(found["procedure"]["body"]["contains_entry"])
        data = self.ask("resolve_containing_procedure", {"document": None, "address": self.greeting_address})
        self.assertEqual((data["found"], data["reason"]), (False, "not_in_procedure"))
        outside = self.ask("resolve_containing_procedure", {"document": None, "address": "0xdeadbeef00"})
        self.assertEqual(outside["reason"], "outside_segments")

    def test_procedure_address_resolves_names_and_addresses(self):
        for selector in ("main", self.main_address, self.main_address[2:]):
            self.assertEqual(
                self.ask("procedure_address", {"document": None, "procedure": selector}),
                self.main_address,
            )
        self.ask_failure("procedure_address", {"document": None, "procedure": "no_such_function"}, "not_found")

    def test_search_inventories_by_literal_and_regex(self):
        literal = self.ask(
            "search_strings",
            {"pattern": "HELLO REA", "mode": "literal", "case_sensitive": False, "document": None},
        )
        self.assertEqual([item["address"] for item in literal], [self.greeting_address])
        exact_case = self.ask(
            "search_strings",
            {"pattern": "HELLO REA", "mode": "literal", "case_sensitive": True, "document": None},
        )
        self.assertEqual(exact_case, [])
        regex = self.ask(
            "search_procedures",
            {"pattern": "^ma.n$", "mode": "regex", "case_sensitive": True, "document": None},
        )
        self.assertEqual([item["value"] for item in regex], ["main"])
        message = self.ask_failure(
            "search_procedures",
            {"pattern": "(", "mode": "regex", "case_sensitive": True, "document": None},
            "invalid_request",
        )
        self.assertIn("Unclosed group", message)

    def test_inspect_native_load_image_measures_the_target(self):
        result = self.ask("inspect_native_load_image")
        self.assertEqual(result["source_files"][0]["original_sha256"], sha256_of(self.target))
        self.assertTrue(result["mappings"])
        for mapping in result["mappings"]:
            self.assertGreater(mapping["length"], 0)
            self.assertEqual(mapping["sha256"] is None, not mapping["initialized"])
        self.assertTrue(result["entry_points"])

    def test_set_address_name_commits_only_with_readback(self):
        unmapped = hex(int(self.add_address, 16) + 0x10000000)
        self.assertTrue(
            self.ask("set_address_name", {"document": None, "address": self.add_address, "name": "renamed_add"})
        )
        self.assertEqual(
            self.ask("address_name", {"document": None, "address": self.add_address}), "renamed_add"
        )
        self.assertEqual(
            self.ask("procedure_address", {"document": None, "procedure": "renamed_add"}),
            self.add_address,
        )
        self.ask_failure("set_address_name", {"document": None, "address": unmapped, "name": "x"}, "invalid_request")
        self.assertEqual(
            self.ask("address_name", {"document": None, "address": self.add_address}), "renamed_add"
        )

    def test_set_address_name_rejects_unrepresentable_text(self):
        before = self.ask("address_name", {"document": None, "address": self.greeting_address})
        message = self.ask_failure(
            "set_address_name",
            {"document": None, "address": self.greeting_address, "name": "bad\u0000name"},
            "invalid_request",
        )
        self.assertIn("NUL", message)
        self.assertEqual(
            self.ask("address_name", {"document": None, "address": self.greeting_address}), before
        )

    def test_set_addresses_names_applies_each_address_independently(self):
        base = int(self.greeting_address, 16)
        first, second, third = (hex(base + offset) for offset in (2, 3, 4))
        result = self.ask(
            "set_addresses_names",
            {"document": None, "names": {
                first: "batch_one", second: "batch_two", "zz": "unparseable", "0xdeadbeef00": "unmapped",
            }},
        )
        self.assertEqual(result, {first: True, second: True, "zz": False, "0xdeadbeef00": False})
        conflict = self.ask(
            "set_addresses_names",
            {"document": None, "names": {third: "alias_one", third[2:]: "alias_two"}},
        )
        self.assertEqual(conflict, {third: False, third[2:]: False})
        self.assertIsNone(self.ask("address_name", {"document": None, "address": third}))
        self.assertEqual(self.ask("address_name", {"document": None, "address": first}), "batch_one")


@unittest.skipUnless(ENABLED, "pyGhidra tests require REA_TEST_PYGHIDRA=1")
class TestBridgeLifecycle(unittest.TestCase):
    """Each test owns a bridge so that endings, failures and cleanup stay observable."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="rea-pyg-fixture-")
        cls.target = build_fixture(cls.directory)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory, ignore_errors=True)

    def launch(self, **overrides):
        bridge = BridgeProcess(self.target, **overrides)
        self.addCleanup(bridge.dispose)
        return bridge

    def assert_clean_exit(self, bridge):
        self.assertEqual(bridge.wait_exit(), 0, bridge.log()[-4000:])
        self.assertFalse(os.path.exists(bridge.endpoint), "socket file must be removed")
        self.assertFalse(os.path.exists(bridge.descriptor_path), "bearer descriptor must be consumed")
        project = os.path.join(bridge.root, "project")
        self.assertEqual(os.listdir(project), [], "ephemeral project files must be deleted")

    def test_shutdown_acknowledges_and_deletes_the_ephemeral_project(self):
        bridge = self.launch()
        client = bridge.connect()
        self.assertTrue(os.path.isdir(os.path.join(bridge.root, "project")))
        self.assertEqual(oct(os.stat(bridge.endpoint).st_mode & 0o777), "0o600")
        response = client.request("shutdown")
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"], {"shutdown": True, "project_ephemeral": True})
        client.close()
        self.assert_clean_exit(bridge)

    def test_silent_peer_that_disconnects_ends_the_session_cleanly(self):
        bridge = self.launch()
        peer = bridge.connect()
        time.sleep(1)
        self.assertIsNone(bridge.process.poll(), "a silent peer must not crash the bridge")
        peer.close()
        self.assert_clean_exit(bridge)

    def test_malformed_frame_is_answered_then_the_connection_closes(self):
        bridge = self.launch()
        client = bridge.connect()
        client.send_raw(b"not json\n")
        response = client.read_response()
        self.assertEqual(response["ok"], False)
        self.assertEqual(response["error"]["code"], "invalid_request")
        self.assertIsNone(client.read_response())
        client.close()
        self.assert_clean_exit(bridge)

    def test_request_with_unexpected_fields_is_malformed(self):
        bridge = self.launch()
        client = bridge.connect()
        frame = {"id": 1, "token": TOKEN, "method": "ping", "params": {}, "extra": True}
        client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        self.assertEqual(client.read_response()["error"]["code"], "invalid_request")
        client.close()
        self.assert_clean_exit(bridge)

    def test_imported_digest_mismatch_fails_before_serving(self):
        bridge = self.launch(target_sha256="0" * 64)
        self.assertNotEqual(bridge.wait_exit(timeout=STARTUP_TIMEOUT_SECONDS), 0)
        self.assertIn("imported-byte digest does not match", bridge.log())
        self.assertFalse(os.path.exists(bridge.endpoint))

    def test_unknown_analyzer_fails_before_serving(self):
        bridge = self.launch(disabled_analyzers=["No Such Analyzer"])
        self.assertNotEqual(bridge.wait_exit(timeout=STARTUP_TIMEOUT_SECONDS), 0)
        self.assertIn("Unknown Ghidra analyzer", bridge.log())
        self.assertFalse(os.path.exists(bridge.endpoint))

    def test_descriptor_with_unknown_fields_is_refused(self):
        bridge = self.launch(surprise="yes")
        self.assertNotEqual(bridge.wait_exit(timeout=STARTUP_TIMEOUT_SECONDS), 0)
        self.assertIn("descriptor fields are invalid", bridge.log())


if __name__ == "__main__":
    unittest.main()
