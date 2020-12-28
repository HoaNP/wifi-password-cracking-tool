#   from Crypto.Cipher import AES
#   from pbkdf2 import PBKDF2
#   import os
#
#   salt = os.urandom(8)    # 64-bit salt
#   key = PBKDF2("This passphrase is a secret.", salt).read(32) # 256-bit key
#   iv = os.urandom(16)     # 128-bit IV
#   cipher = AES.new(key, AES.MODE_CBC, iv)
#     ...
#
# Sample crypt() usage:
# from pbkdf2 import crypt
# pwhash = crypt("secret")
# alleged_pw = raw_input("Enter password: ")
# if pwhash == crypt(alleged_pw, pwhash):
# 	print "Password good"
# else:
# 	print "Invalid password"

from pbkdf2 import PBKDF2
import codecs

def strtoint(s ):
	return int (codecs.encode(s, 'hex'), 16)

def cs(a):
	return codecs.decode(a,'hex')


passphrase = "secret"
essid = "1111"
f = PBKDF2 (passphrase, essid, 4096)
pmk = f.read (32)
s = cs('abcd')
print(strtoint(s))
