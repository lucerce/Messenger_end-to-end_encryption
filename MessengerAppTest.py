import unittest
import base64
from MessengerApp import CryptoUtils

class TestKeyExchange(unittest.TestCase):

    def test_dh_key_exchange(self):
        # Обидві сторони повинні отримати однаковий ключ
        priv1, pub1 = CryptoUtils.generate_dh_keys()
        priv2, pub2 = CryptoUtils.generate_dh_keys()
        key1 = CryptoUtils.derive_key(priv1, pub2)
        key2 = CryptoUtils.derive_key(priv2, pub1)
        self.assertEqual(key1, key2)

    def test_key_length(self):
        # Перевірка довжини ключа (32 байти для AES-256)
        priv1, pub1 = CryptoUtils.generate_dh_keys()
        priv2, pub2 = CryptoUtils.generate_dh_keys()
        key = CryptoUtils.derive_key(priv1, pub2)
        self.assertEqual(len(key), 32)

class TestEncryption(unittest.TestCase):

    def setUp(self):
        # Підготовка спільного ключа перед кожним тестом
        priv1, pub1 = CryptoUtils.generate_dh_keys()
        priv2, pub2 = CryptoUtils.generate_dh_keys()
        self.key = CryptoUtils.derive_key(priv1, pub2)

    def test_encrypt_decrypt(self):
        # Перевірка коректного шифрування та розшифрування
        message = "Hello"
        encrypted = CryptoUtils.encrypt(self.key, message)
        decrypted = CryptoUtils.decrypt(self.key, encrypted)
        self.assertEqual(message, decrypted)

    def test_encrypt_randomness(self):
        # Однакові повідомлення повинні мати різний шифротекст
        msg = "Same message"
        enc1 = CryptoUtils.encrypt(self.key, msg)
        enc2 = CryptoUtils.encrypt(self.key, msg)
        self.assertNotEqual(enc1["ciphertext"], enc2["ciphertext"])

    def test_decrypt_with_wrong_key(self):
        # Розшифрування неправильним ключем має викликати помилку
        priv, pub = CryptoUtils.generate_dh_keys()
        wrong_key = CryptoUtils.derive_key(priv, pub)
        encrypted = CryptoUtils.encrypt(self.key, "secret")
        with self.assertRaises(Exception):
            CryptoUtils.decrypt(wrong_key, encrypted)

class TestSignature(unittest.TestCase):

    def test_signature_valid(self):
        # Коректний підпис повинен проходити перевірку
        priv, pub = CryptoUtils.generate_sign_keys()
        message = b"test message"
        signature = priv.sign(message)
        pub.verify(signature, message)  # не повинно бути помилки

    def test_signature_invalid(self):
        # Підпис має ламатися при зміні повідомлення
        priv, pub = CryptoUtils.generate_sign_keys()
        message = b"test message"
        bad_message = b"fake message"
        signature = priv.sign(message)
        with self.assertRaises(Exception):
            pub.verify(signature, bad_message)

class TestPayload(unittest.TestCase):

    def test_payload_structure(self):
        # Перевірка структури зашифрованого повідомлення
        priv1, pub1 = CryptoUtils.generate_dh_keys()
        priv2, pub2 = CryptoUtils.generate_dh_keys()

        key = CryptoUtils.derive_key(priv1, pub2)
        encrypted = CryptoUtils.encrypt(key, "data")

        self.assertIn("nonce", encrypted)
        self.assertIn("ciphertext", encrypted)

        # Перевірка Base64
        base64.b64decode(encrypted["nonce"])
        base64.b64decode(encrypted["ciphertext"])