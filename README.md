# DeriveHelper
DeriveHelper is a script that helps with KDFs. A KDF (Key Derivation Function) is a function of which derives a cryptographic key from a password. DeriveHelper allows for creation of passwords, salts, and deriving the cryptographic key. DeriveHelper currently supports the following KDFs:

Bcrypt
Scrypt
PBKDF2HMAC
Argon2I
Argon2ID

# Derive Usage
```python
import derivehelper

password = derivehelper.create_pw(64) # Create a 64 character long password
salt = derivehelper.create_pw(32) # Create a 32 character long salt

'''
The Derive class takes in 3 arguments.
1. The password to derive the key from.
2. The salt to use for the KDF.
3. The KDF to use.
'''
d = derivehelper.Derive(password, salt, derivehelper.KDF.BCRYPT)
'''
To actually derive the key, call the derive() method.
The Bcrypt KDF by default, generates a key of which is 32 bytes long, and 100 rounds. The byte value can be changed 
by passing in an integer for the first parameter. You can also get a base64 encoded version by passing in encode=True
'''
print(d.derive()) # b'H\x15\xbb\xb7\xcaQ\xee\xa1\xfe-\xa51\xca\x8d\x12\xfe5\xd2h!\xd9\xeaV\xc6\xfbp3L\x98(`\x97'
# For a 56 byte key
print(d.derive(56)) # b'H\x1c\x15\xca\xbb \xb7l\xcaIQ\x9c\xee8\xa1\x98\xfe\xa3-\xf9\xa5\xf61&\xca\x8b\x8d\t\x12\x17\xfeN57\xd2hh\xa4!\x0f\xd9s\xeaHV\x08\xc6\xb3\xfb\xe9p\xc03\x91L\xe9'
# For base64 encoded output.
print(d.derive(56, encode=True)) # 'SBwVyrsgt2zKSVGc7jihmP6jLfml9jEmyouNCRIX/k41N9JoaKQhD9lz6khWCMaz++lwwDORTOk='
```
* Optional Arguments
```python
import derivehelper

password = derivehelper.create_pw(64)
salt = derivehelper.create_pw(32)

d = derivehelper.Derive(password, salt, derivehelper.KDF.BCRYPT)
'''
The derive() method has another optional argument called extra_args, of which is a tuple.
This is where you can pass in KDF-specific additional options. In this example since I'm 
using bcrypt, I can pass in a different rounds value via this extra_args argument.

I will pass in 150 for 150 rounds. It is 100 by default.
'''
print(d.derive(extra_args=(150,))) # b'B\x089\x96\xbbf|\xfe\xb0\xd9\x93+\x9f\x88\x00\xfbFW\xd2\x8f>\xd2\xb10\x1f\xff\x94>\xf5\xffV#'

'''
PBKDF2HMAC also has support for this argument. It will control the iteration value.
By default it is 150,000. But can be overridden.
'''
d = derivehelper.Derive(password, salt, derivehelper.KDF.PBKDF2HMAC)
# Using 250,000 iterations.
d.derive(extra_args=(250000,)) # b'\xcd\x15\xd6~\xceC\xa2r\xcf\x93KCS;E\x13\xac\x9b\x7f\xdf\xe7Tt\x89H\x0c\x84\xe4\xc1\xdau\x94'
```
# Hash Usage
* CUSTOM using() FUNCTIONALITY COMING SOON!
* Supported hashing functions: Argon2ID, Argon2I, Argon2D, Bcrypt, Bcrypt_SHA256, PBKDF2-SHA1, PBKDF2-SHA256, PBKDF2-SHA512, SHA256-crypt, SHA512-crypt, Scrypt.
```python
import derivehelper

password = derivehelper.create_pw(32) # Create 32 char password

'''
To utilize the hashing functions of derivehelper, instantiate the Hash class.
The Hash class takes in 1 parameter, the password (labeled "secret").
'''
h = derivehelper.Hash(password)

# To get the hash value, call the method of which corresponds to the hash you want.
# For argon2id
print(h.argon2id()) # $argon2id$v=19$m=102400,t=2,p=8$P0foXQuB8D4npDRGqLW21g$vGpZF/z9erC3sVFcZls2Gw
# For bcrypt
print(h.bcrypt()) # $2b$12$oov7QnFVNxKSi/6AgxsfMudfX3NaC.sqmVMqEHozDd2.hgTJrMslO
# For PBKDF2-SHA256
print(h.pbkdf2_sha256()) # $pbkdf2-sha256$29000$x3hPScm5915LqTVm7J0Tgg$P9/FNmie9ONydtCzcII9BPA/7XD5NHqnixvP9NFWoVQ
# For SHA256-crypt
print(h.sha256_crypt()) # $5$rounds=535000$vOEY9PcYv.fTIgAB$/NOB/DAqAvo/SQe6ckxVOJOqWahlosBItvuQAItVVf.
```

# Important Notes
* 1. When using Argon2I or Argon2ID KDFs, they both only support a fixed salt size of 16 bytes. 
     Creation of such can be done simply with urandom or the create_pw function. Just pass in 16 for bytes/length.
* 2. Scrypt, Argon2ID, and Argon2I are the only KDFs that do not support the extra_args parameter.
