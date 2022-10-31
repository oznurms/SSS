from tinyec.ec import SubGroup
from tinyec.ec import Curve
from Crypto.Random.random import randint
from numpy.polynomial.polynomial import Polynomial
import numpy as np
from eth_hash.auto import keccak

from ecdsa import SigningKey, SECP256k1
import random
import binascii

p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
g = (x, y)

field = SubGroup(p, g, n, 1)
curve = Curve(a=0, b=7, field=field, name='secp256k1')
#Randomly generated private key private_key = randint(1, n)
private_key = 90018174909883363932818018705933554615527813777786211547049804476635176037803


public_key = private_key * curve.g
#"04"+str(hex(public_key.x)[2:])+str(hex(public_key.y)[2:])
#print(f"Public_key:{public_key}")
print(f"Public_key:{hex(public_key.x)[2:],hex(public_key.y)[2:]}")



rd_nm = 68694766151625942319581660452878651676495341859664045306510006106785254895650
#print(f"Random number: {rd_nm}")

# n=3,t=2 threshold
f = np.poly1d([rd_nm, private_key])
#print(f"Polynomial: {f}")
print('Key shares: ')
print(f"f(1): {(1, f(1))}")
print(f"f(2): {(2, f(2))}")
print(f"f(3): {(3, f(3))}")

x,y = input("Choose two shares to distribute: ").split()

print("First share: ", x)
print("Second share: ", y)

print("Distribute shares")



#This polynomial is evaluated by Lagrange interpolation. Its constant term is secret.
t = np.poly1d([68694766151625942319581660452878651676495341859664045306510006106785254895650,
               90018174909883363932818018705933554615527813777786211547049804476635176037803])


#Wallet address
print("Address")
print(f"0x{keccak(b'public_key').hex()[24:64]}")





hex_string = '{:02x}'.format(t(0))
hex_string=bytes(hex_string, 'utf-8')
hex_string=binascii.unhexlify(hex_string)
#print(f"Private_key (hex): {hex_string.hex()}")
priv = SigningKey.from_string(hex_string, curve=SECP256k1)


pub = priv.get_verifying_key()


#print(f"Public_key in verification: {pub}")
print("Signing")
print("Enter the message in the message file")
with open("message", "rb") as f:
    me = f.read()
sig = priv.sign(me)
print(f"message is: {me}")

with open("signature", "wb") as f:
    f.write(sig)
#print(f"Signature: {sig.hex()}")
print(f"The signature on the public file: {sig.hex()}")


with open("signature", "rb") as f:
   data = f.read()



print("Signature verification")


print(f"Public_key (hex): {pub}")
print(f"Signature (hex): {sig.hex()}")

print(f"Signature valid or not: {pub.verify(sig, me)}")


from ecdsa import SigningKey, NIST384p
sk = SigningKey.generate(curve=NIST384p)
vk = sk.verifying_key
vk.precompute()
signature = sk.sign(b"message")
assert vk.verify(signature, b"message")


