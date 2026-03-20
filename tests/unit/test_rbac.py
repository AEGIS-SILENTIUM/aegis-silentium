"""Unit tests for AEGIS RBAC module."""
import hashlib
import hmac
import json
import time
import unittest
from unittest.mock import MagicMock, patch

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../c2"))

from auth.rbac import (
    RBACManager, _hash_key, _verify_key, _jwt_sign, _jwt_verify,
    role_has, ROLES, ROLE_PERMISSIONS,
)


class TestKeyHashing(unittest.TestCase):
    def test_hash_and_verify_roundtrip(self):
        raw = "super-secret-key-2026"
        hashed = _hash_key(raw)
        self.assertTrue(_verify_key(raw, hashed))

    def test_wrong_key_fails(self):
        hashed = _hash_key("correct-key")
        self.assertFalse(_verify_key("wrong-key", hashed))

    def test_hash_uses_salt(self):
        raw = "same-key"
        h1 = _hash_key(raw)
        h2 = _hash_key(raw)
        # Different salts → different hashes
        self.assertNotEqual(h1, h2)
        # But both verify
        self.assertTrue(_verify_key(raw, h1))
        self.assertTrue(_verify_key(raw, h2))

    def test_empty_key_fails_gracefully(self):
        hashed = _hash_key("valid")
        self.assertFalse(_verify_key("", hashed))

    def test_malformed_hash_fails_gracefully(self):
        self.assertFalse(_verify_key("key", "no_dollar_sign"))


class TestJWT(unittest.TestCase):
    SECRET = b"test-jwt-secret-32bytes-00000000"

    def _make_token(self, exp_offset=3600, **extra):
        payload = {"sub": "op1", "role": "operator", "jti": "abc", "type": "access",
                   "iat": time.time(), "exp": time.time() + exp_offset, **extra}
        return _jwt_sign(payload, self.SECRET), payload

    def test_sign_and_verify(self):
        token, payload = self._make_token()
        decoded = _jwt_verify(token, self.SECRET)
        self.assertEqual(decoded["sub"], "op1")
        self.assertEqual(decoded["role"], "operator")

    def test_expired_token_rejected(self):
        token, _ = self._make_token(exp_offset=-1)
        with self.assertRaises(ValueError) as ctx:
            _jwt_verify(token, self.SECRET)
        self.assertIn("expired", str(ctx.exception))

    def test_tampered_signature_rejected(self):
        token, _ = self._make_token()
        # Flip last character
        token = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaises(ValueError):
            _jwt_verify(token, self.SECRET)

    def test_wrong_secret_rejected(self):
        token, _ = self._make_token()
        with self.assertRaises(ValueError):
            _jwt_verify(token, b"wrong-secret-00000000000000000000")

    def test_malformed_token_rejected(self):
        with self.assertRaises(ValueError):
            _jwt_verify("not.a.valid.jwt.at.all", self.SECRET)


class TestRolePermissions(unittest.TestCase):
    def test_admin_has_all_permissions(self):
        self.assertTrue(role_has("admin", "payloads:generate"))
        self.assertTrue(role_has("admin", "secrets:rotate"))
        self.assertTrue(role_has("admin", "operators:set_role"))

    def test_ghost_read_only(self):
        self.assertTrue(role_has("ghost", "dashboard:view"))
        self.assertFalse(role_has("ghost", "tasks:create"))
        self.assertFalse(role_has("ghost", "payloads:generate"))
        self.assertFalse(role_has("ghost", "listeners:create"))

    def test_operator_can_create_tasks(self):
        self.assertTrue(role_has("operator", "tasks:create"))
        self.assertTrue(role_has("operator", "chat:post"))
        self.assertFalse(role_has("operator", "listeners:create"))
        self.assertFalse(role_has("operator", "surveillance:delete"))

    def test_senior_can_create_listeners(self):
        self.assertTrue(role_has("senior", "listeners:create"))
        self.assertTrue(role_has("senior", "exploits:create"))
        self.assertFalse(role_has("senior", "operators:create"))
        self.assertFalse(role_has("senior", "secrets:rotate"))

    def test_lead_can_manage_operators(self):
        self.assertTrue(role_has("lead", "operators:create"))
        self.assertTrue(role_has("lead", "operators:deactivate"))
        self.assertTrue(role_has("lead", "audit:view"))
        self.assertFalse(role_has("lead", "secrets:rotate"))

    def test_role_inheritance(self):
        # Lead has all senior permissions
        for perm in ROLE_PERMISSIONS["senior"]:
            self.assertTrue(role_has("lead", perm),
                            f"lead should inherit senior perm: {perm}")

    def test_invalid_role_has_no_permissions(self):
        self.assertFalse(role_has("superuser", "dashboard:view"))
        self.assertFalse(role_has("", "dashboard:view"))


class TestRBACManager(unittest.TestCase):
    def setUp(self):
        self.conn = MagicMock()
        self.cursor = MagicMock()
        self.conn.cursor.return_value.__enter__ = lambda s: self.cursor
        self.conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        self.pg_fn = lambda: self.conn
        self.redis = MagicMock()
        self.redis.exists.return_value = True
        self.redis.get.return_value = None
        self.secret = b"test-secret-32bytes-00000000"
        self.mgr = RBACManager(self.pg_fn, self.redis, self.secret)

    def test_authenticate_valid_credentials(self):
        key = "valid-op-key"
        key_hash = _hash_key(key)
        self.cursor.fetchone.return_value = (key_hash, "operator", True, 0, None)
        result = self.mgr.authenticate("op1", key, ip="127.0.0.1")
        self.assertIn("access_token", result)
        self.assertIn("refresh_token", result)
        self.assertEqual(result["operator"], "op1")
        self.assertEqual(result["role"], "operator")

    def test_authenticate_wrong_key_raises(self):
        key_hash = _hash_key("correct-key")
        self.cursor.fetchone.return_value = (key_hash, "operator", True, 0, None)
        with self.assertRaises(PermissionError):
            self.mgr.authenticate("op1", "wrong-key")

    def test_authenticate_unknown_operator_raises(self):
        self.cursor.fetchone.return_value = None
        with self.assertRaises(PermissionError):
            self.mgr.authenticate("unknown", "any-key")

    def test_authenticate_inactive_operator_raises(self):
        key_hash = _hash_key("key")
        self.cursor.fetchone.return_value = (key_hash, "operator", False, 0, None)
        with self.assertRaises(PermissionError) as ctx:
            self.mgr.authenticate("op1", "key")
        self.assertIn("deactivated", str(ctx.exception))

    def test_verify_access_token_valid(self):
        key = "key"
        key_hash = _hash_key(key)
        self.cursor.fetchone.return_value = (key_hash, "operator", True, 0, None)
        tokens = self.mgr.authenticate("op1", key)
        # Redis still returns truthy for session key
        self.redis.exists.return_value = True
        session = self.mgr.verify_access_token(tokens["access_token"])
        self.assertEqual(session.operator, "op1")
        self.assertEqual(session.role, "operator")

    def test_verify_access_token_revoked(self):
        key = "key"
        key_hash = _hash_key(key)
        self.cursor.fetchone.return_value = (key_hash, "operator", True, 0, None)
        tokens = self.mgr.authenticate("op1", key)
        # Simulate revocation
        self.redis.exists.return_value = False
        with self.assertRaises(PermissionError) as ctx:
            self.mgr.verify_access_token(tokens["access_token"])
        self.assertIn("revoked", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
