import random
import hashlib

class digitalSignature:
    def __init__(self):
        # Define elliptic curve parameters
        self.p = pow(2, 255) - 19
        self.base = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
        self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        self.b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0
        self.private_key = 16065771662800155919777244270557635166338919379921972017126734669803662752766
        self.public_key = self.apply_double_and_add_method(self.base, self.private_key)

    def gcd(self, a, b):
        while a != 0:
            a, b = b % a, a
        return b

    # Function to find the modular inverse of a mod m
    def find_mod_inverse(self, a, m):
        if a < 0:
            a = (a + m * int(abs(a) / m) + m) % m

        # no mod inverse if a & m aren't relatively prime
        if self.gcd(a, m) != 1:
            return None

        # Calculate using the Extended Euclidean Algorithm:
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % m

    def apply_double_and_add_method(self, P, k):
        addition_point = P

        k_as_binary = bin(k)
        k_as_binary = k_as_binary[2:len(k_as_binary)]

        for i in range(1, len(k_as_binary)):
            current_bit = k_as_binary[i: i + 1]

            # always apply doubling
            addition_point = self.point_addition(addition_point, addition_point)

            if current_bit == '1':
                # add base point
                addition_point = self.point_addition(addition_point, P)

        return addition_point

    # Function to calculate the point addition
    def point_addition(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if P != Q:
            m = (y2 - y1) * self.find_mod_inverse(x2 - x1, self.p) % self.p
        else:
            m = (3 * x1 ** 2 + self.a) * self.find_mod_inverse(2 * y1, self.p) % self.p

        x3 = (m ** 2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return x3, y3

    def sign(self, message):

        # Calculate public key = base * private key

        message_hash = self.hashing(message)
        # Choose a random number k in the range [1..p-1]
        k = self.hashing(message_hash + message) % self.p

        # Calculate random point on elliptic curve R = k * base
        R = self.apply_double_and_add_method(self.base, k)

        # Calculate h = hash(R_x + public_key_x + message)
        h = self.hashing(R[0] + self.public_key[0] + message) % self.p
        print("R[0]_sign: ",self.public_key)
        # Calculate s = (k + h * private_key) % p
        s = (k + h * self.private_key)
        print("s_sign: ", s)
        return R[0], s

    def verify(self, message, signature):
        R, s = signature
        h = self.hashing(R[0] + self.public_key[0] + message) % self.p

        P1 = self.apply_double_and_add_method(self.base, s)
        P2 = self.point_addition(R, self.apply_double_and_add_method(self.public_key, h))
        print("P1: ",P1)
        print("P2: ",P2)
        print("R[0]_ve: ", self.public_key)
        print("s_verify: ",s)
        print(self.public_key)
        return P1[0] == P2[0] and P1[1] == P2[1]

    def text_to_int(self, text):
        encoded_text = text.encode('utf-8')
        hex_text = encoded_text.hex()
        int_text = int(hex_text, 16)
        return int_text

    def hashing(self, message):

        return int(hashlib.sha256(str(message).encode("utf-8")).hexdigest(), 16)

if __name__ == "__main__":
    ds = digitalSignature()

    # Generate a random private key

    # Sign a message
    message = "Hello world"
    message_int = ds.text_to_int(message)
    signature = ds.sign(message_int)

    print("----------------------")
    print("Signing:")
    print("Message: ", message)
    print("Signature (R, s): ", signature)
    print("----------------------")

    # Verify the signature
    print("")
    if ds.verify(message_int, signature):
        print("The Signature is valid")
    else:
        print("The Signature violation detected!")