import unittest
import random
from des import encrypt, decrypt
import helper

class TestDES(unittest.TestCase):

    def testBasicEN_FIXEDKEY(self):
        key = [0, 252, 132, 99, 12, 3, 17, 5]
        plaintext = "Python is an interpreted, high-level, general-purpose programming language. " \
                    "It was created by Guido van Rossum and first released in 1991."
        ciphertext = encrypt(key, plaintext)
        self.assertTrue(decrypt(key, ciphertext) == plaintext)

    def testBasicEN_RANDKEY(self):
        key = []
        for _ in range(8):
            key.append(random.randint(0, 255))
        plaintext = "Python is an interpreted, high-level, general-purpose programming language. " \
                    "It was created by Guido van Rossum and first released in 1991."
        ciphertext = encrypt(key, plaintext)
        self.assertTrue(decrypt(key, ciphertext) == plaintext)

    def testOnlyNumbers(self):
        key = []
        for _ in range(8):
            key.append(random.randint(0, 255))
        plaintext = "1 231 3123 111"
        ciphertext = encrypt(key, plaintext)
        print(helper.byte_to_str(ciphertext))
        self.assertTrue(decrypt(key, ciphertext) == plaintext)

    def testShortKey(self):
        key = [0, 252, 132, 99, 12]
        self.assertRaises(AssertionError, lambda: encrypt(key, "ala"))

    def testLongKey(self):
        key = [0, 252, 132, 99, 12, 3, 17, 5, 156]
        self.assertRaises(AssertionError, lambda: encrypt(key, "ma"))

    def testWrongKeyValPos(self):
        key = [0, 252, 132, 99, 12, 3, 17, 999]
        self.assertRaises(AssertionError, lambda: encrypt(key, "kota"))

    def testWrongKeyValNeg(self):
        key = [0, 252, 132, 99, 12, 3, 17, -3]
        self.assertRaises(AssertionError, lambda: encrypt(key, "kota"))

if __name__ == "__main__":
    unittest.main()

