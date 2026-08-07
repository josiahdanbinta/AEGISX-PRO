"""
Unit tests for AEGIS core security module.
"""
import pytest
from app.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    create_refresh_token,
    create_reset_token,
    decode_token,
    generate_api_key,
    hash_api_key,
    generate_secure_token,
    generate_otp,
    generate_hmac_signature,
    verify_hmac_signature,
    mask_string,
    mask_email,
)


class TestPasswordHashing:
    def test_hash_password_returns_string(self):
        hashed = hash_password("TestPassword123!")
        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")

    def test_verify_correct_password(self):
        password = "SecureP@ssw0rd2024"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_incorrect_password(self):
        hashed = hash_password("CorrectPassword1!")
        assert verify_password("WrongPassword1!", hashed) is False

    def test_hash_is_unique_per_call(self):
        password = "SamePassword1!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2


class TestPasswordStrength:
    def test_valid_password(self):
        valid, error = validate_password_strength("Str0ng!Passw0rd")
        assert valid is True
        assert error is None

    def test_password_too_short(self):
        valid, error = validate_password_strength("Sh0rt!")
        assert valid is False
        assert "12 characters" in error.lower()

    def test_password_missing_uppercase(self):
        valid, error = validate_password_strength("alllowercase1!")
        assert valid is False
        assert "uppercase" in error.lower()

    def test_password_missing_digits(self):
        valid, error = validate_password_strength("NoDigitsHere!")
        assert valid is False
        assert "digit" in error.lower()

    def test_password_missing_special(self):
        valid, error = validate_password_strength("NoSpecialChar123")
        assert valid is False
        assert "special" in error.lower()


class TestJWT:
    def test_create_and_decode_access_token(self):
        token = create_access_token("user-123", "tenant-456", ["soc_analyst"])
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["tenant_id"] == "tenant-456"
        assert payload["roles"] == ["soc_analyst"]
        assert payload["type"] == "access"

    def test_create_and_decode_refresh_token(self):
        token = create_refresh_token("user-123", "tenant-456")
        payload = decode_token(token)
        assert payload is not None
        assert payload["type"] == "refresh"
        assert payload["sub"] == "user-123"

    def test_create_and_decode_reset_token(self):
        token = create_reset_token("user-123", "tenant-456")
        payload = decode_token(token)
        assert payload is not None
        assert payload["type"] == "reset"

    def test_decode_invalid_token(self):
        payload = decode_token("invalid.token.here")
        assert payload is None

    def test_decode_empty_token(self):
        payload = decode_token("")
        assert payload is None


class TestAPIKeys:
    def test_generate_api_key_format(self):
        key = generate_api_key()
        assert key.startswith("AEGIS_")
        assert len(key) > 30

    def test_generate_api_key_uniqueness(self):
        keys = [generate_api_key() for _ in range(10)]
        assert len(set(keys)) == 10

    def test_hash_api_key_consistent(self):
        key = "AEGIS_abcdef1234567890fedcba0987654321"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)
        assert hash1 == hash2

    def test_hash_api_key_is_sha256_hex(self):
        hashed = hash_api_key("test_key")
        assert len(hashed) == 64
        assert all(c in "0123456789abcdef" for c in hashed.lower())


class TestSecureRandom:
    def test_generate_secure_token_length(self):
        token = generate_secure_token(32)
        decoded = token.replace("-", "").replace("_", "")
        assert len(decoded) >= 32

    def test_generate_secure_token_uniqueness(self):
        tokens = [generate_secure_token() for _ in range(20)]
        assert len(set(tokens)) == 20

    def test_generate_otp_length(self):
        otp = generate_otp(6)
        assert len(otp) == 6
        assert otp.isdigit()

    def test_generate_otp_custom_length(self):
        otp = generate_otp(8)
        assert len(otp) == 8


class TestHMAC:
    def test_sign_and_verify(self):
        payload = "test-payload"
        signature = generate_hmac_signature(payload)
        assert verify_hmac_signature(payload, signature) is True

    def test_verify_tampered_payload(self):
        payload = "original-data"
        signature = generate_hmac_signature(payload)
        assert verify_hmac_signature("tampered-data", signature) is False

    def test_sign_with_custom_key(self):
        key = "custom-secret-key"
        signature = generate_hmac_signature("data", key)
        assert verify_hmac_signature("data", signature, key) is True
        assert verify_hmac_signature("data", signature) is False


class TestMasking:
    def test_mask_string_normal(self):
        masked = mask_string("sensitive_value", visible_chars=4)
        assert masked == "sens************"

    def test_mask_short_string(self):
        masked = mask_string("ab", visible_chars=4)
        assert masked == "**"

    def test_mask_email(self):
        masked = mask_email("john.doe@company.com")
        assert "@" in masked
        assert "j" == masked[0]
        assert "e@company.com" in masked


class TestExceptionClasses:
    def test_import_exceptions(self):
        from app.core.exceptions import (
            AEGISException,
            AuthenticationError,
            AuthorizationError,
            NotFoundError,
            ValidationError,
            ConflictError,
            RateLimitError,
            AccountLockedError,
            AccountSuspendedError,
            PasswordExpiredError,
            MFARrequiredError,
            TenantQuotaExceededError,
        )
        assert AEGISException is not None
        assert AuthenticationError("test").status_code == 401
        assert AuthorizationError("test").status_code == 403
        assert NotFoundError("Resource", "id").status_code == 404
        assert ValidationError("test").status_code == 422
