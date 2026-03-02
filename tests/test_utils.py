import string

from src.utils import generate_random_password


def test_generate_random_password_default_length() -> None:
    password = generate_random_password()
    assert len(password) == 16


def test_generate_random_password_custom_length() -> None:
    password = generate_random_password(32)
    assert len(password) == 32


def test_generate_random_password_uses_supported_characters() -> None:
    allowed = set(string.ascii_letters + string.digits + string.punctuation)
    password = generate_random_password(64)
    assert set(password).issubset(allowed)


def test_generate_random_password_has_mixed_character_types() -> None:
    password = generate_random_password(64)
    assert any(c in string.ascii_letters for c in password)
    assert any(c in string.digits for c in password)
    assert any(c in string.punctuation for c in password)
