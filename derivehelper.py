from nacl import pwhash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as pbkdf2
from enum import Enum, auto
import bcrypt
import hashlib
import base64
import secrets
import string

PW_DATASET = string.ascii_letters + string.digits

class KDF(Enum):
    ARGON2ID = auto()
    ARGON2I = auto()
    BCRYPT = auto()
    PBKDF2HMAC = auto()
    SCRYPT = auto()

class exceptions:
    class NotDerivedError(Exception):
        def __init__(self, message='Key has not been derived.'):
            self.message = message
            super().__init__(self.message)

e = exceptions()

def create_pw(password_length: int = 16):
    if type(password_length) != int:
        raise ValueError('Password length must be an integer.')
    return b''.join(secrets.choice(PW_DATASET).encode() for _ in range(password_length))

def create_salt(password: bytes):
    if type(password) != bytes:
        raise ValueError('Password must be in byte form.')
    password_hash0 = hashlib.sha3_256(password).hexdigest()[:6]
    password_hash1 = hashlib.sha3_512(password).hexdigest()[-6:]
    return f'${password_hash0}$${password_hash1}$'.encode()

class Derive:
    def __init__(self, password, salt, KDF_function: KDF = KDF.ARGON2ID):
        self.KDF_function = KDF_function
        if (KDF_function == KDF.ARGON2ID or KDF_function == KDF.ARGON2I) and not len(salt) == 16:
            raise ValueError(f'Salt must be exactly 16 bytes long for {KDF_function}')
        self.password = password
        self.salt = salt
        if type(salt) != bytes:
            raise ValueError('Salt must be in byte form.')
        elif type(password) != bytes:
            raise ValueError('Password must be in byte form.')
    
    def derive(self, desired_bytes=32, extra_args: tuple=(), encode=False):
        if type(extra_args) != tuple:
            raise ValueError('Extra arguments must be a tuple')
        
        if self.KDF_function == KDF.ARGON2ID:
            key = pwhash.argon2id.kdf(desired_bytes, self.password, self.salt)
        elif self.KDF_function == KDF.ARGON2I:
            key = pwhash.argon2i.kdf(desired_bytes, self.password, self.salt)
        elif self.KDF_function == KDF.BCRYPT:
            if len(extra_args) < 1:
                key = bcrypt.kdf(self.password, self.salt, desired_bytes, 100)
            else:
                key = bcrypt.kdf(self.password, self.salt, desired_bytes, *extra_args)
        elif self.KDF_function == KDF.PBKDF2HMAC:
            if len(extra_args) < 1:
                _kdf = pbkdf2(hashes.SHA3_512(), desired_bytes, self.salt, 150000)
            else:
                _kdf = pbkdf2(hashes.SHA3_512(), desired_bytes, self.salt, *extra_args)
            key = _kdf.derive(self.password)
        elif self.KDF_function == KDF.SCRYPT:
            _kdf = Scrypt(self.salt, desired_bytes, n=2**14, r=8, p=1)
            key = _kdf.derive(self.password)
        else:
            raise ValueError('KDF_function is not valid.')
        
        if encode:
            key = base64.b64encode(key).decode()
        return key

def main():
    salt = create_salt(b'password')
    d = Derive(b'password', salt*192, KDF.SCRYPT)
    print(d.derive())

if __name__ == '__main__':
    main()
