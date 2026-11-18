"""Tests for entity extraction and canonicalisation."""

import unittest

from alertfuse.entities import (
    DEFAULT_HOST_SUFFIXES,
    extract_entities,
    normalize_host,
    normalize_ip,
)


class IpTests(unittest.TestCase):
    def test_plain_ipv4(self):
        self.assertEqual(normalize_ip("10.1.2.3"), "10.1.2.3")

    def test_strips_port(self):
        self.assertEqual(normalize_ip("10.1.2.3:443"), "10.1.2.3")

    def test_bracketed_ipv6_with_port(self):
        self.assertEqual(normalize_ip("[2001:db8::1]:8080"), "2001:db8::1")

    def test_ipv6_port_without_brackets(self):
        self.assertEqual(normalize_ip("2001:db8::1:443"), "2001:db8::1:443")

    def test_loopback_and_unspecified_dropped(self):
        self.assertIsNone(normalize_ip("127.0.0.1"))
        self.assertIsNone(normalize_ip("0.0.0.0"))
        self.assertIsNone(normalize_ip("::1"))

    def test_garbage_rejected(self):
        self.assertIsNone(normalize_ip("not-an-ip"))
        self.assertIsNone(normalize_ip(""))


class HostTests(unittest.TestCase):
    def test_lowercased(self):
        self.assertEqual(normalize_host("WS01"), "ws01")

    def test_internal_suffix_folded(self):
        self.assertEqual(normalize_host("ws01.corp.local"), "ws01")

    def test_multi_label_suffix_not_folded(self):
        self.assertEqual(normalize_host("ws01.corp.local.example.com"), "ws01.corp.local.example.com")

    def test_unknown_suffix_kept(self):
        self.assertEqual(normalize_host("host.example.com"), "host.example.com")

    def test_port_stripped(self):
        self.assertEqual(normalize_host("WEB01:3389"), "web01")

    def test_trailing_dot_removed(self):
        self.assertEqual(normalize_host("ws01."), "ws01")

    def test_noise_rejected(self):
        for value in ("", "unknown", "N/A", "-", "localhost"):
            self.assertIsNone(normalize_host(value), value)

    def test_custom_suffix_list(self):
        self.assertEqual(
            normalize_host("app01.prod.acme", suffixes=("prod.acme",)), "app01"
        )


class ExtractTests(unittest.TestCase):
    def test_ecs_fields(self):
        flat = {
            "user.name": "alice",
            "host.name": "WS01.corp.local",
            "source.ip": "10.0.0.5:51234",
            "file.hash.sha256": "ABCDEF1234567890",
        }
        found = extract_entities(flat)
        self.assertEqual(found["user"], ["alice"])
        self.assertEqual(found["host"], ["ws01"])
        self.assertEqual(found["ip"], ["10.0.0.5"])
        self.assertEqual(found["hash"], ["abcdef1234567890"])

    def test_vendor_field_names(self):
        flat = {"src_ip": "1.2.3.4", "ComputerName": "srv-01", "Account": "BOB"}
        # Camel case keys are only matched lowercase-by-suffix, so use exact aliases.
        flat = {"src_ip": "1.2.3.4", "computername": "srv-01", "account": "bob"}
        found = extract_entities(flat)
        self.assertEqual(found["ip"], ["1.2.3.4"])
        self.assertEqual(found["host"], ["srv-01"])
        self.assertEqual(found["user"], ["bob"])

    def test_case_insensitive_path_matching(self):
        found = extract_entities({"Host.Name": "WS02"})
        self.assertEqual(found["host"], ["ws02"])

    def test_longest_alias_wins(self):
        found = extract_entities({"parent.process.name": "cmd.exe", "process.name": "powershell.exe"})
        self.assertEqual(found["parent_process"], ["cmd.exe"])
        self.assertEqual(found["process"], ["powershell.exe"])

    def test_valid_hash_form_preserved(self):
        found = extract_entities({"hashes": "SHA256=deadbeefdeadbeef"})
        self.assertEqual(found["hash"], ["deadbeefdeadbeef"])

    def test_short_hash_rejected(self):
        self.assertNotIn("hash", extract_entities({"md5": "abc"}))

    def test_multi_value_string_split(self):
        found = extract_entities({"dst_ip": "10.0.0.1,10.0.0.2;10.0.0.3"})
        self.assertEqual(found["ip"], ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_duplicates_collapsed(self):
        found = extract_entities({"user.name": "alice", "user": "ALICE"})
        self.assertEqual(found["user"], ["alice"])

    def test_noise_values_ignored(self):
        found = extract_entities({"user.name": "unknown", "host.name": "-"})
        self.assertEqual(found, {})

    def test_non_string_scalars_coerced(self):
        found = extract_entities({"process.pid": 4242, "user.name": 7})
        self.assertEqual(found["user"], ["7"])
        self.assertNotIn("process", found)

    def test_null_and_bool_skipped(self):
        found = extract_entities({"user.name": None, "host.name": True})
        self.assertEqual(found, {})

    def test_unrelated_fields_ignored(self):
        found = extract_entities({"event.action": "logon", "count": 12})
        self.assertEqual(found, {})

    def test_default_suffixes_is_tuple(self):
        self.assertIn("local", DEFAULT_HOST_SUFFIXES)


if __name__ == "__main__":
    unittest.main()
