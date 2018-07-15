from Crypto.Cipher import AES
from Crypto import Random
import json
from json.decoder import JSONDecodeError
from typing import Tuple, Dict


class Payload:

    def __init__(self, key: bytes, plaintext=None, ciphertext=None):

        self.key = key

        if plaintext:
            self.plaintext = plaintext
            self.ciphertext, self.iv = self.encrypt()

        elif ciphertext:
            self.ciphertext = ciphertext
            self.plaintext, self.iv = self.decrypt()

        else:
            pass
            # TODO: raise custom exception

    def encrypt(self) -> Tuple[bytes, bytes]:

        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext_str = json.dumps(self.plaintext)
        pt_len = len(plaintext_str)
        buffer_size = AES.block_size - pt_len % AES.block_size

        return cipher.encrypt(plaintext_str + " " * buffer_size), iv

    def decrypt(self) -> Tuple[Dict, bytes]:

        iv = self.ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext_str = cipher.decrypt(self.ciphertext)[AES.block_size:].rstrip().decode("utf-8")
        try:
            return json.loads(plaintext_str), iv
        except JSONDecodeError as e:
            print(e)
            return {}, iv

    def pack(self) -> bytes:

        return self.iv + self.ciphertext
