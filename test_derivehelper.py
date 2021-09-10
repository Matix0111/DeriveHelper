import unittest
import bcrypt
import derivehelper
from nacl import pwhash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

pw = derivehelper.create_pw(64)
salt = derivehelper.create_pw(16)

banner = f"""
-----STARTING UNITTEST-----
    PASSWORD: {pw.decode()}
\tSALT: {salt.decode()}
---------------------------
"""

print(banner)

class Test_Derivehelper(unittest.TestCase):
    def test_bcrypt(self):
        d = derivehelper.Derive(pw, salt, derivehelper.KDF.BCRYPT)
        proper_bcrypt = bcrypt.kdf(pw, salt, 32, 100)
        self.assertEqual(proper_bcrypt, d.derive())

    def test_argon2i(self):
        d = derivehelper.Derive(pw, salt, derivehelper.KDF.ARGON2I)
        proper_argon2i = pwhash.argon2i.kdf(32, pw, salt)
        self.assertEqual(proper_argon2i, d.derive())

    def test_argon2id(self):
        d = derivehelper.Derive(pw, salt, derivehelper.KDF.ARGON2ID)
        proper_argon2id = pwhash.argon2id.kdf(32, pw, salt)
        self.assertEqual(proper_argon2id, d.derive())

    def test_scrypt(self):
        d = derivehelper.Derive(pw, salt, derivehelper.KDF.SCRYPT)
        proper_scrypt = Scrypt(salt, 32, 2**14, 8, 1)
        self.assertEqual(proper_scrypt.derive(pw), d.derive())
    
    def test_pbkdf2(self):
        d = derivehelper.Derive(pw, salt, derivehelper.KDF.PBKDF2HMAC)
        proper_pbkdf2 = PBKDF2HMAC(hashes.SHA3_512(), 32, salt, 150000)
        self.assertEqual(proper_pbkdf2.derive(pw), d.derive())

if __name__ == '__main__':
    unittest.main()