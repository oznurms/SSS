from tinyec.ec import SubGroup
from tinyec.ec import Curve
from Crypto.Random.random import randint
from numpy.polynomial.polynomial import Polynomial
import numpy as np
from eth_hash.auto import keccak
from ecdsa import SigningKey, SECP256k1
import random
import binascii

import random
from math import ceil
from decimal import Decimal
from fractions import Fraction
p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)  # prime number
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)  # the order of the base point g
x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
g = (x, y)

field = SubGroup(p, g, n, 1)
curve = Curve(a=0, b=7, field=field, name='secp256k1')
# Randomly generated private key private_key = randint(1, n)
private_key = 90018174909883363932818018705933554615527813777786211547049804476635176037803

public_key = private_key * curve.g
print(f"Public_key:{hex(public_key.x)[2:], hex(public_key.y)[2:]}")

rd_nm = 68694766151625942319581660452878651676495341859664045306510006106785254895650


# (t,n)=(2,3) threshold
f = np.poly1d([rd_nm, private_key])
print(f'Secret key: {private_key}')


def generation(n, m, secret):
    "Example: 3 parties with threshold 2"
    # coefficients = coeff(m, secret)
    shares = []

    for i in range(1, 4):
        x = random.randrange(1, 10) 
        shares.append((x, f(x)))
    print("Distributed shares: ", shares)
    #print(f'Shares: {", ".join(str(share) for share in shares)}')
    return shares


#for j, share_j in enumerate(shares):
 #   print(list(enumerate(shares,2)))


def get_secret(shares):
    " Lagranges interpolation."
    sums = 0
    prod_arr = []

    for j, share_j in enumerate(shares):
        xj, yj = share_j
        prod = Fraction(1)
        for i, share_i in enumerate(shares):
            xi, _ = share_i
            if i != j:
                prod *= Fraction(xi,(xi - xj))

        prod *= yj
        sums += Fraction(prod)
    return int(Fraction(sums))


shares = generation(3, 2, private_key)
W = random.sample(shares, 2)
print(f'Selected shares for constructing the private key: {", ".join(str(share) for share in W)}')
R=get_secret(W)
print(f'Obtained secret:{R}')
print(f'Obtained secret is the private key: {R == private_key}')


# #Wallet address
print(f'A Wallet address for a party:')
print(f"0x{keccak(b'public_key').hex()[24:64]}")

hex_string = '{:02x}'.format(R)
hex_string=bytes(hex_string, 'utf-8')
hex_string=binascii.unhexlify(hex_string)
#print(f"Private_key (hex): {hex_string.hex()}")
priv = SigningKey.from_string(hex_string, curve=SECP256k1)


pub = priv.get_verifying_key()


#print(f"Public_key in verification: {pub}")
print("Signing operation")
print("Enter the message in the message file")
with open("message", "rb") as f:
    me = f.read()
    sig = priv.sign(me)
print(f"Message is: {me}")

with open("signature", "wb") as f:
    f.write(sig)
print(f"The signature on the public file: {sig.hex()}")


with open("signature", "rb") as f:
    data = f.read()

print("Signature verification")
#print(f"Public_key (hex): {pub}")
print(f"Signature (hex): {sig.hex()}")
print(f"Signature valid or not: {pub.verify(sig, me)}")


from ecdsa import SigningKey, NIST384p
sk = SigningKey.generate(curve=NIST384p)
vk = sk.verifying_key
vk.precompute()
signature = sk.sign(b"message")
assert vk.verify(signature, b"message")


