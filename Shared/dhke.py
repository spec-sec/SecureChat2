"""
Diffie-Hellman Key Exchange class for establishing a shared key.
"""

from Crypto import Random
from hashlib import sha256

__author__ = "spec"
__license__ = "MIT"
__version__ = "0.1"
__status__ = "Development"

# Size of prime number in bits (recommended minimum: 2048)
DH_SIZE = 2048

# Length (in bytes) of each variable for public transport
LEN_PRIME = 1024
LEN_GEN = 16
LEN_PK = 1024

# Total public transport message size (in bytes)
DH_MSG_SIZE = LEN_PRIME + LEN_GEN + LEN_PK


class DH:

    def __init__(self, p: int, g: int, pk: int):
        """
        Initialize a new DH object for key exchange between client and server.
        :param p: a prime number from the multiplicative group of integers modulo n
        :param g: primitive root modulo
        :param pk: public key generated from p, g, and a private key
        """
        self.p = p
        self.g = g
        self.pk = pk

    @staticmethod
    def gen_private_key() -> int:
        """
        Generate a random private key.
        :return: a random integer of length DH_SIZE
        """
        return DH.b2i(Random.new().read(DH_SIZE))

    @staticmethod
    def gen_public_key(g: int, private: int, p: int) -> int:
        """
        Generate a public key from g, p, and a private key.
        :param g: primitive root modulo
        :param private: private key
        :param p: prime number
        :return: public key as an integer
        """
        return pow(g, private, p)

    @staticmethod
    def get_shared_key(public: int, private: int, p: int) -> bytes:
        """
        Calculate a shared key from a foreign public key, a local private
        key, and a shared prime.
        :param public: public key as an integer
        :param private: private key as an integer
        :param p: prime number
        :return: shared key as a 256-bit bytes object
        """
        s = int(pow(public, private, p))
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
        return sha256(s_bytes).digest()

    @staticmethod
    def b2i(bts: bytes) -> int:
        """
        Convert a bytes object to an integer.
        :param bts: bytes to convert
        :return: integer
        """
        return int.from_bytes(bts, byteorder="big")

    def __dict__(self):

        return {'p': self.p, 'g': self.g, 'pk': self.pk}


class InvalidDH(Exception):

    def __init__(self, message):
        self.message = message
