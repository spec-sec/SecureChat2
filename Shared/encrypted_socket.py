import socket
import json
from typing import Optional, Tuple, Dict
from Shared.constants import *
from Shared.cipher import Payload


class EncryptedSocket:

    def __init__(self, connection: socket.socket):

        self.connection = connection
        self.key = None

    def recv(self, num_bytes: int) -> Optional[bytes]:
        try:
            data = self.connection.recv(num_bytes)
            if not data:
                self.connection.close()
                return None
        except OSError:
            self.connection.close()
            return None
        return data

    def process_packet(self) -> Tuple[int, bytes]:
        # Length [3 bytes]
        length_data = self.recv(LENGTH_SIZE)
        if not length_data:
            raise ConnectionError
        length = int.from_bytes(length_data, byteorder='big')
        # Mode [1 Byte]
        mode_data = self.recv(MODE_SIZE)
        if not mode_data:
            raise ConnectionError
        mode = int.from_bytes(mode_data, byteorder='big')
        # Payload [x Bytes]
        payload_data = self.recv(length)
        if not payload_data:
            raise ConnectionError
        return mode, payload_data

    def decrypt_payload_data(self, payload_data: bytes) -> Dict:
        assert self.key is not None
        return Payload(self.key, ciphertext=payload_data).plaintext

    def get_plaintext_packet(self) -> Dict:
        mode, payload_data = self.process_packet()
        if mode == ClientMode.DH:
            return json.loads(payload_data.decode('utf-8'))
        else:
            return self.decrypt_payload_data(payload_data)

    def send(self, payload: Dict, mode: int):
        if mode == ClientMode.DH:
            payload_bytes = json.dumps(payload).encode("utf-8")
        else:
            payload_bytes = Payload(self.key, plaintext=payload).pack()
        length = len(payload_bytes)
        length_bytes = length.to_bytes(LENGTH_SIZE, byteorder="big")
        mode_bytes = mode.to_bytes(MODE_SIZE, byteorder="big")
        self.connection.send(length_bytes + mode_bytes + payload_bytes)
