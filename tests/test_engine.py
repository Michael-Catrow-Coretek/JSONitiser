"""Unit tests for JSONitizerEngine."""

import unittest

from engine import JSONitizerEngine


# ---------------------------------------------------------------------------
# Flat key detection
# ---------------------------------------------------------------------------

class TestFlatKeyDetection(unittest.TestCase):
    def setUp(self):
        self.e = JSONitizerEngine()

    def test_user_name(self):
        out = self.e.sanitize({"user.name": "john.doe"})
        self.assertEqual(out["user.name"], "<USER_1>")

    def test_username(self):
        out = self.e.sanitize({"username": "jdoe"})
        self.assertEqual(out["username"], "<USER_1>")

    def test_employee_id(self):
        out = self.e.sanitize({"employee_id": "E12345"})
        self.assertEqual(out["employee_id"], "<USER_1>")

    def test_full_name(self):
        out = self.e.sanitize({"full_name": "Jane Smith"})
        self.assertEqual(out["full_name"], "<USER_1>")

    def test_last_name(self):
        out = self.e.sanitize({"last_name": "Smith"})
        self.assertEqual(out["last_name"], "<USER_1>")

    def test_email(self):
        out = self.e.sanitize({"email": "john@example.com"})
        self.assertEqual(out["email"], "<EMAIL_1>")

    def test_host_name(self):
        out = self.e.sanitize({"host.name": "web-server-01"})
        self.assertEqual(out["host.name"], "<HOST_1>")

    def test_organization_name(self):
        out = self.e.sanitize({"organization.name": "AcmeCorp"})
        self.assertEqual(out["organization.name"], "<ORG_1>")


# ---------------------------------------------------------------------------
# Nested key detection (builds dotted path during traversal)
# ---------------------------------------------------------------------------

class TestNestedKeyDetection(unittest.TestCase):
    def setUp(self):
        self.e = JSONitizerEngine()

    def test_nested_user_name(self):
        out = self.e.sanitize({"user": {"name": "jane.smith"}})
        self.assertEqual(out["user"]["name"], "<USER_1>")

    def test_nested_user_email(self):
        out = self.e.sanitize({"user": {"email": "jane@corp.com"}})
        self.assertEqual(out["user"]["email"], "<EMAIL_1>")

    def test_nested_host_name(self):
        out = self.e.sanitize({"host": {"name": "prod-server"}})
        self.assertEqual(out["host"]["name"], "<HOST_1>")

    def test_nested_organization_name(self):
        out = self.e.sanitize({"organization": {"name": "AcmeCorp"}})
        self.assertEqual(out["organization"]["name"], "<ORG_1>")

    def test_three_level_winlog_user_name(self):
        out = self.e.sanitize({"winlog": {"user": {"name": r"CORP\jdoe"}}})
        self.assertEqual(out["winlog"]["user"]["name"], "<USER_1>")

    def test_source_user_name(self):
        out = self.e.sanitize({"source": {"user": {"name": "attacker"}}})
        self.assertEqual(out["source"]["user"]["name"], "<USER_1>")


# ---------------------------------------------------------------------------
# IP preservation
# ---------------------------------------------------------------------------

class TestIPPreservation(unittest.TestCase):
    def setUp(self):
        self.e = JSONitizerEngine()

    def test_source_ip(self):
        out = self.e.sanitize({"source": {"ip": "192.168.1.1"}})
        self.assertEqual(out["source"]["ip"], "192.168.1.1")

    def test_destination_ip(self):
        out = self.e.sanitize({"destination": {"ip": "10.0.0.5"}})
        self.assertEqual(out["destination"]["ip"], "10.0.0.5")

    def test_client_ip(self):
        out = self.e.sanitize({"client": {"ip": "172.16.0.1"}})
        self.assertEqual(out["client"]["ip"], "172.16.0.1")

    def test_server_ip(self):
        out = self.e.sanitize({"server": {"ip": "8.8.8.8"}})
        self.assertEqual(out["server"]["ip"], "8.8.8.8")

    def test_ipv6_preserved(self):
        out = self.e.sanitize({"source": {"ip": "2001:db8::1"}})
        self.assertEqual(out["source"]["ip"], "2001:db8::1")

    def test_ip_in_unstructured_message_not_replaced(self):
        out = self.e.sanitize({"message": "Request from 192.168.1.100"})
        self.assertIn("192.168.1.100", out["message"])


# ---------------------------------------------------------------------------
# Regex on unstructured strings
# ---------------------------------------------------------------------------

class TestRegexOnUnstructuredStrings(unittest.TestCase):
    def setUp(self):
        self.e = JSONitizerEngine()

    def test_email_in_message(self):
        out = self.e.sanitize({"message": "Contact john@example.com for help"})
        self.assertIn("<EMAIL_1>", out["message"])
        self.assertNotIn("john@example.com", out["message"])

    def test_multiple_emails_in_message(self):
        out = self.e.sanitize({"message": "From alice@a.com to bob@b.com"})
        self.assertIn("<EMAIL_1>", out["message"])
        self.assertIn("<EMAIL_2>", out["message"])

    def test_ws_hostname(self):
        out = self.e.sanitize({"message": "Login from WS-12345"})
        self.assertIn("<HOST_1>", out["message"])
        self.assertNotIn("WS-12345", out["message"])

    def test_laptop_hostname(self):
        out = self.e.sanitize({"message": "Session on LAPTOP-ABCDE"})
        self.assertIn("<HOST_1>", out["message"])

    def test_desktop_hostname(self):
        out = self.e.sanitize({"message": "Accessed from DESKTOP-XYZ99"})
        self.assertIn("<HOST_1>", out["message"])

    def test_pc_hostname(self):
        out = self.e.sanitize({"message": "Device PC-1AB2 connected"})
        self.assertIn("<HOST_1>", out["message"])

    def test_hostname_case_insensitive(self):
        out = self.e.sanitize({"message": "laptop-ABCDE is online"})
        self.assertIn("<HOST_1>", out["message"])


# ---------------------------------------------------------------------------
# Value consistency — same raw value always produces the same placeholder
# ---------------------------------------------------------------------------

class TestConsistencyAndMapping(unittest.TestCase):
    def setUp(self):
        self.e = JSONitizerEngine()

    def test_same_value_in_two_user_keys(self):
        out = self.e.sanitize({"user.name": "john.doe", "username": "john.doe"})
        self.assertEqual(out["user.name"], out["username"])
        self.assertEqual(out["user.name"], "<USER_1>")

    def test_different_values_get_sequential_placeholders(self):
        out = self.e.sanitize({"user.name": "alice", "username": "bob"})
        placeholders = {out["user.name"], out["username"]}
        self.assertEqual(placeholders, {"<USER_1>", "<USER_2>"})

    def test_email_consistent_across_key_and_regex(self):
        out = self.e.sanitize(
            {
                "email": "alice@corp.com",
                "message": "Sent alert to alice@corp.com",
            }
        )
        self.assertEqual(out["email"], "<EMAIL_1>")
        self.assertIn("<EMAIL_1>", out["message"])
        self.assertNotIn("alice@corp.com", out["message"])


# ---------------------------------------------------------------------------
# Stateless reset — new engine instance starts fresh
# ---------------------------------------------------------------------------

class TestStatelessReset(unittest.TestCase):
    def test_counters_restart_on_new_instance(self):
        e1 = JSONitizerEngine()
        e2 = JSONitizerEngine()
        r1 = e1.sanitize({"user.name": "alice"})
        r2 = e2.sanitize({"user.name": "bob"})
        self.assertEqual(r1["user.name"], "<USER_1>")
        self.assertEqual(r2["user.name"], "<USER_1>")

    def test_mapping_does_not_bleed_between_instances(self):
        e1 = JSONitizerEngine()
        e1.sanitize({"user.name": "alice"})
        e2 = JSONitizerEngine()
        r2 = e2.sanitize({"user.name": "alice"})
        self.assertEqual(r2["user.name"], "<USER_1>")
        self.assertEqual(e2.counters["USER"], 1)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.e = JSONitizerEngine()

    def test_empty_string_value_returned_as_is(self):
        out = self.e.sanitize({"user.name": ""})
        self.assertEqual(out["user.name"], "")

    def test_whitespace_only_value_returned_as_is(self):
        out = self.e.sanitize({"user.name": "   "})
        self.assertEqual(out["user.name"], "   ")

    def test_none_value_untouched(self):
        out = self.e.sanitize({"user.name": None})
        self.assertIsNone(out["user.name"])

    def test_integer_value_untouched(self):
        out = self.e.sanitize({"event": {"duration": 12345}})
        self.assertEqual(out["event"]["duration"], 12345)

    def test_boolean_value_untouched(self):
        out = self.e.sanitize({"event": {"success": True}})
        self.assertTrue(out["event"]["success"])

    def test_unrelated_list_untouched(self):
        out = self.e.sanitize({"tags": ["network", "alert"]})
        self.assertEqual(out["tags"], ["network", "alert"])

    def test_deeply_nested_dict(self):
        data = {"a": {"b": {"c": {"user": {"name": "deep_user"}}}}}
        out = self.e.sanitize(data)
        self.assertEqual(out["a"]["b"]["c"]["user"]["name"], "<USER_1>")

    def test_non_ascii_username(self):
        out = self.e.sanitize({"user.name": "Ångström"})
        self.assertEqual(out["user.name"], "<USER_1>")

    def test_mixed_sensitive_and_ip_in_same_doc(self):
        data = {
            "user": {"name": "jdoe"},
            "source": {"ip": "10.1.2.3"},
            "host": {"name": "dc01"},
        }
        out = self.e.sanitize(data)
        self.assertEqual(out["user"]["name"], "<USER_1>")
        self.assertEqual(out["source"]["ip"], "10.1.2.3")
        self.assertEqual(out["host"]["name"], "<HOST_1>")


if __name__ == "__main__":
    unittest.main()
