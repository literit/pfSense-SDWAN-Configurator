import string
import unittest

from src.utils import generate_random_password


class GenerateRandomPasswordTests(unittest.TestCase):
    def test_default_length(self) -> None:
        password = generate_random_password()
        self.assertEqual(len(password), 16)

    def test_custom_length(self) -> None:
        for length in [8, 24, 32]:
            with self.subTest(length=length):
                password = generate_random_password(length)
                self.assertEqual(len(password), length)

    def test_characters_are_valid(self) -> None:
        valid_chars = set(string.ascii_letters + string.digits + string.punctuation)
        password = generate_random_password(100)
        for char in password:
            self.assertIn(char, valid_chars)

    def test_uniqueness(self) -> None:
        passwords = {generate_random_password(24) for _ in range(10)}
        self.assertGreater(len(passwords), 1)


if __name__ == "__main__":
    unittest.main()
