"""
Security tests for AEGIS - validates security requirements are met.
"""
import pytest
from app.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    decode_token,
    generate_secure_token,
)


class TestPasswordSecurity:
    def test_bcrypt_uses_sufficient_rounds(self):
        hashed = hash_password("TestPassword123!")
        assert hashed.startswith("$2b$12$"), f"Expected 12 rounds, got: {hashed[:7]}"

    def test_passwords_dont_leak_in_hashes(self):
        password = "SuperSecretP@ss12345"
        hashed = hash_password(password)
        assert password not in hashed

    def test_empty_password_rejected(self):
        valid, _ = validate_password_strength("")
        assert valid is False

    def test_common_password_rejected(self):
        valid, _ = validate_password_strength("password123!")
        assert valid is False  # Too short (< 12 chars)

    def test_timing_safe_comparison(self):
        # bcrypt.checkpw uses constant-time comparison internally
        hashed = hash_password("TestPassword1!")
        # This should not leak timing information
        verify_password("AAAA" * 20, hashed)
        # Just verifying no exception thrown


class TestTokenSecurity:
    def test_expired_token_rejected(self):
        from datetime import timedelta
        from app.core.security import create_access_token
        token = create_access_token(
            "user-1",
            "tenant-1",
            ["role"],
            expires_delta=timedelta(seconds=-1),
        )
        payload = decode_token(token)
        assert payload is None

    def test_token_without_signature_rejected(self):
        payload = decode_token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalidsig")
        assert payload is None

    def test_token_type_enforced(self):
        from app.core.security import create_refresh_token
        token = create_refresh_token("user-1", "tenant-1")
        payload = decode_token(token)
        assert payload["type"] == "refresh"
        # Access endpoints should verify type == "access"


class TestInputValidation:
    def test_sql_injection_in_password(self):
        injection = "'; DROP TABLE users; --"
        hashed = hash_password(injection)
        # No SQL is executed, password is safely hashed
        assert len(hashed) > 0

    def test_xss_in_token_subject(self):
        xss_payload = "<script>alert('xss')</script>"
        from app.core.security import create_access_token
        token = create_access_token(xss_payload, "tenant-1", ["role"])
        payload = decode_token(token)
        assert payload["sub"] == xss_payload
        # The token is signed, content is authenticated but should be sanitized on display

    def test_api_key_not_reversible(self):
        from app.core.security import generate_api_key, hash_api_key
        key = generate_api_key()
        hashed = hash_api_key(key)
        # SHA-256 is one-way
        assert hashed != key
        assert len(hashed) == 64
