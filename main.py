# Python program to implement
# ECDSA
p = pow(2, 255) - 19

base = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296\
    ,0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b

# Function for typecasting from
# string to int
def textToInt(text):
    encoded_text = text.encode('utf-8')
    hex_text = encoded_text.hex()
    int_text = int(hex_text, 16)
    return int_text


# Function to find the modular inverse
# of a mod m
def findModInverse(a, m):
    if a < 0:
        a = (a + m * int(abs(a) / m) + m) % m

    # no mod inverse if a & m aren't
    # relatively prime
    if gcd(a, m) != 1:
        return None

    # Calculate using the Extended
    # Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        # // is the integer division operator
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def applyDoubleAndAddMethod(P, k, a, mod):
    additionPoint = (P[0], P[1])

    # 0b1111111001
    kAsBinary = bin(k)

    # 1111111001
    kAsBinary = kAsBinary[2:len(kAsBinary)]
    # print(kAsBinary)

    for i in range(1, len(kAsBinary)):
        currentBit = kAsBinary[i: i + 1]

        # always apply doubling
        additionPoint = pointAddition(additionPoint, additionPoint, a, mod)

        if currentBit == '1':
            # add base point
            additionPoint = pointAddition(additionPoint, P, a,  mod)

    return additionPoint

# Function to calculate the point addition
def pointAddition(P, Q, a, mod):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if P != Q:
        m = (y2 - y1) * findModInverse(x2-x1,mod) % mod
    else:
        m = (3 * x1**2 + a) * findModInverse(2 * y1, mod) % mod

    x3 = (m**2 - x1 - x2) % mod
    y3 = (m * (x1 - x3) - y1) % mod

    return (x3, y3)


# y^2 = x^3 + ax + b (mod p)
# secp256r1
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0

x0 = base[0]
y0 = base[1]

print("----------------------")
print("Key Generation: ")

import random

# Chọn ngẫu nhiên một số nguyên 256 bit làm private key
privateKey = random.getrandbits(256)

print("private key: ",privateKey)
# Tính public key = base * private key
publicKey = applyDoubleAndAddMethod(base, privateKey, a,  p)
print("public key: ", publicKey)

message= "Hello world"
message = textToInt(message)
print("message: ", message)
print("p: ", p)

def hashing(message):
    import hashlib
    return int(hashlib.sha256(str(message).encode("utf-8")).hexdigest(), 16)

print("hash(message): ",hashing(message))
# Chọn một số k ngẫu nhiên nằm trong phạm vi [1..p-1]
k = hashing(hashing(message) + message) % p
print("k: ",k)
# Tính điểm ngẫu nhiên trên đường cong elliptic R
# R = k * base
R = applyDoubleAndAddMethod(base, k, a,  p)
# Hàm băm của một chuỗi thông tin cụ thể
h = hashing(R[0] + publicKey[0] + message) % p
print("h: ",h)
# Tính bằng chứng chữ ký
# % p
s = (k + h * privateKey)
print("s: ",s)

print("----------------------")
print("Signing:")
print("message: ", message)
print("Signature (R, s)")
print("R: ", R)
print("s: ", s)
print("p: ", p)

# -----------------------------------
# verify
h = hashing(R[0] + publicKey[0] + message) % p
P1 = applyDoubleAndAddMethod(base, s, a, p)
P2 = pointAddition(R, applyDoubleAndAddMethod(publicKey, h, a, p), a, p)

print("----------------------")
print("Verification:")
print("P1: ", P1)
print("P2: ", P2)
print("----------------------")
print("result")
if P1[0] == P2[0] and P1[1] == P2[1]:
    print("The Signature is valid")
else:
    print("The Signature violation detected!")