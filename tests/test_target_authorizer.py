"""
Unit Tests for Target Authorization & Scope Control Module
Validates strict lab allowlists, syntax checks, CIDR rejection, and public target bans.
"""

import unittest
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.authorization.target_authorizer import (
    TargetAuthorizer,
    TargetAuthorizationError,
    TargetSyntaxError
)
from src.schema import TargetAuthorizationRecord


class TestTargetAuthorizer(unittest.TestCase):

    def setUp(self):
        self.authorizer = TargetAuthorizer()

    def test_default_target_authorization(self):
        """Verifies default target is authorized lab target 192.168.56.111."""
        auth = self.authorizer.authorize_target()
        self.assertIsInstance(auth, TargetAuthorizationRecord)
        self.assertEqual(auth.target, "192.168.56.111")
        self.assertTrue(auth.authorized)
        self.assertEqual(auth.authorization_status, "AUTHORIZED_LOCAL_LAB")
        self.assertEqual(auth.category, "intentionally_vulnerable_lab")

    def test_old_target_192_168_56_107_is_unauthorized(self):
        """Verifies requirement 3: 192.168.56.107 is strictly unauthorized after IP migration."""
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("192.168.56.107")

    def test_explicit_authorized_target(self):
        """Verifies explicitly authorized local target 127.0.0.1."""
        auth = self.authorizer.authorize_target("127.0.0.1", profile="lab-safe-minimal")
        self.assertEqual(auth.target, "127.0.0.1")
        self.assertTrue(auth.authorized)
        self.assertEqual(auth.scan_profile, "lab-safe-minimal")

    def test_unauthorized_private_ip_rejection(self):
        """Verifies that an unlisted private IP is rejected."""
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("192.168.1.100")

    def test_unauthorized_public_ip_rejection(self):
        """Verifies that public routable IPs are strictly rejected."""
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("8.8.8.8")
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("1.1.1.1")

    def test_cidr_range_rejection(self):
        """Verifies that subnet / CIDR notations are rejected."""
        with self.assertRaises(TargetSyntaxError):
            self.authorizer.authorize_target("192.168.56.0/24")
        with self.assertRaises(TargetSyntaxError):
            self.authorizer.authorize_target("10.0.0.0/8")

    def test_url_protocol_scheme_rejection(self):
        """Verifies that URL protocol prefixes are rejected."""
        with self.assertRaises(TargetSyntaxError):
            self.authorizer.authorize_target("http://192.168.56.111")
        with self.assertRaises(TargetSyntaxError):
            self.authorizer.authorize_target("https://localhost")

    def test_shell_metacharacters_rejection(self):
        """Verifies that shell injection characters are trapped and rejected."""
        unsafe_inputs = [
            "192.168.56.111; ls",
            "192.168.56.111 && cat /etc/passwd",
            "`whoami`",
            "192.168.56.111 | id",
            "192.168.56.111$(id)"
        ]
        for bad in unsafe_inputs:
            with self.assertRaises(TargetSyntaxError):
                self.authorizer.authorize_target(bad)

    def test_unauthorized_hostname_rejection(self):
        """Verifies that external hostnames are rejected for active scanning."""
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("google.com")
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("example.com")

    def test_unauthorized_scan_profile_rejection(self):
        """Verifies that requesting an unpermitted profile for a target raises error."""
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("192.168.56.111", profile="aggressive-exploit-profile")

    def test_reachability_does_not_confer_authorization(self):
        """Verifies rule: reachability check is separate from authorization."""
        # 127.0.0.1 is responsive
        is_up, msg = self.authorizer.verify_target_connectivity("127.0.0.1")
        self.assertTrue(is_up)
        # But an unlisted responsive IP must still be rejected by authorize_target
        with self.assertRaises(TargetAuthorizationError):
            self.authorizer.authorize_target("127.0.0.2")


if __name__ == "__main__":
    unittest.main()

