import sys
import socket
import threading
from M2Crypto import RSA
from M2Crypto.BIO import BIOError, MemoryBuffer
from Crypto import Random
from Shared.constants import *
from Shared.constants import ClientMode
from Shared.dhke import DH
from Shared.encrypted_socket import EncryptedSocket
from typing import List, Dict, Optional
from base64 import b64encode, b64decode


RSA_KEY_LEN = 2048
SESSION_SALT_LEN = 16
SESSION_KEY_LEN = 32
PRIV_KEY_FILE = 'private_key.pem'
PUB_KEY_FILE = 'public_key.pem'


class Client:

    def __init__(self, server_address: str, port=DEFAULT_PORT):

        self.username = None
        self.cookie = None
        self.user_id = None
        self.pub_key = None
        self.requester = Requester(server_address, port)
        self.listener = Listener(server_address, port, self)
        # TODO: generate private key if necessary
        try:
            self.private_key = RSA.load_key(PRIV_KEY_FILE)
        except BIOError:
            print("Private key not found :(")
            self.private_key = None

    def stop(self):
        self.listener.connection.close()
        sys.exit()

    def login(self, username: str, password: str):
        response = self.requester.request({'action': Action.LOGIN,
                                           'username': username,
                                           'password': password})
        cookie = response.get("cookie")
        user_id = response.get("id")
        if cookie and user_id:
            self.username = username
            self.cookie = cookie
            self.user_id = user_id
            self.pub_key = self.get_public_key(self.user_id)
        else:
            # TODO: Throw exception!
            print(response.get("error"))
        self.listener.send({'cookie': self.cookie}, ClientMode.LISTEN)
        threading.Thread(target=self.listener.listen).start()

    def request(self, payload: Dict) -> Dict:
        if self.cookie is not None:
            payload['cookie'] = self.cookie
        return self.requester.request(payload)

    def generate_keys(self):
        key = RSA.gen_key(RSA_KEY_LEN, 65537)
        self.private_key = key
        key.save_key(PRIV_KEY_FILE, None)
        key.save_pub_key(PUB_KEY_FILE)
        f = open(PUB_KEY_FILE, 'r')
        public_key = f.read()
        f.close()
        self.requester.request({'action': Action.SET_KEY,
                                'content': public_key,
                                'cookie': self.cookie})

    def get_session_key(self, session: int) -> bytes:
        response = self.request({'action': Action.GET_SESSION_KEY, 'session': session})
        encrypted_session_key = response.get('session_key')
        if not encrypted_session_key:
            raise Exception('Session key not found :(')
        return self.decrypt_session_key(encrypted_session_key)

    def decrypt_session_key(self, encrypted: str):
        encrypted_bytes = b64decode(encrypted)
        return self.private_key.private_decrypt(encrypted_bytes, RSA.pkcs1_oaep_padding)[SESSION_SALT_LEN:]

    def get_sessions(self) -> List:
        response = self.request({'action': Action.GET_SESSIONS})
        return response['sessions']

    def get_messages(self, session: int) -> List:
        response = self.request({'action': Action.GET_MESSAGES, 'session': session})
        return response['messages']

    @staticmethod
    def load_public_key(pub_key_str: str):
        bio = MemoryBuffer(pub_key_str.encode('utf-8'))
        return RSA.load_pub_key_bio(bio)

    def get_public_key(self, user: int) -> Optional[RSA.RSA_pub]:
        response = self.request({'action': Action.GET_PUBLIC_KEY, 'user': user})
        public_key_str = response['public_key']
        return self.load_public_key(public_key_str)

    def get_username(self, user: int) -> str:
        response = self.request({'action': Action.GET_USERNAME, 'user': user})
        return response['name']

    def create_session(self, members: List[int]):
        session_key = Random.new().read(SESSION_KEY_LEN)
        members_with_keys = []
        for member in members:
            public_key = self.get_public_key(member)
            salt = Random.new().read(SESSION_SALT_LEN)
            encrypted_bytes = public_key.public_encrypt(salt + session_key, RSA.pkcs1_oaep_padding)
            members_with_keys.append((member, b64encode(encrypted_bytes).decode('utf-8')))
        self.request({'action': Action.CREATE_SESSION, 'members': members_with_keys})

    def create_account(self, username: str, password: str, fullname: str):
        response = self.request({'action': Action.CREATE_ACCOUNT,
                                 'username': username,
                                 'password': password,
                                 'fullname': fullname})
        print(response)
        self.user_id = response.get('id')
        self.cookie = response.get('cookie')
        self.generate_keys()


class AuthenticationError(Exception):

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class EncryptedSocketClient(EncryptedSocket):

    def __init__(self, connection: socket.socket):
        super().__init__(connection)

    def dh(self) -> bytes:
        payload = self.get_plaintext_packet()
        p, g, server_key = payload['p'], payload['g'], payload['pk']
        private_key = DH.gen_private_key()
        public_key = DH.gen_public_key(g, private_key, p)
        self.send({'key': public_key}, ClientMode.DH)
        shared_key = DH.get_shared_key(server_key, private_key, p)
        return shared_key


class Requester(EncryptedSocketClient):

    def __init__(self, server_address: str, port: int):
        self.server_address = server_address
        self.port = port
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        super().__init__(connection)
        # TODO: do something else here?
        self.connection.close()

    def request(self, payload: Dict) -> Dict:
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((self.server_address, self.port))
        self.key = self.dh()
        self.send(payload, ClientMode.REQUEST)
        response = self.get_plaintext_packet()
        self.connection.close()
        self.key = None
        return response


class Listener(EncryptedSocketClient):

    def __init__(self, server_address: str, port: int, client: Client):
        self.client = client
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((server_address, port))
        super().__init__(connection)
        self.key = self.dh()
        self.interface = None

    def set_interface(self, interface):
        self.interface = interface

    def listen(self):

        while True:
            try:
                payload = self.get_plaintext_packet()
            except ConnectionError:
                print("Listener connection lost")
                return
            if payload['type'] == 'message':
                self.interface.listener_add_msg(payload)
