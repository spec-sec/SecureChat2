from .client import Client
from typing import Dict, Optional, Any
from base64 import b64encode, b64decode
from Crypto import Random
from Shared.cipher import Payload
from Shared.constants import Action
import dateutil.parser
from datetime import datetime, timezone
from M2Crypto.RSA import RSA_pub


class User:

    def __init__(self, id: int, name: str, pub_key: RSA_pub):
        self.id = id
        self.name = name
        self.pub_key = pub_key

    def __str__(self):
        return self.name


class Message:

    def __init__(self, sender: User, content: str, signature: str, time_sent: datetime):

        self.sender = sender
        self.content = content
        self.signature = signature
        self.time_sent = time_sent

    def __str__(self):
        return "[{}] {}: {}".format(self.time_sent.strftime("%d/%m/%Y %I:%M %p"),
                                    self.sender.name, self.content)


class Session:

    def __init__(self, id: int, key: bytes, members: Dict[int, User], client: Client, offset=0):
        self.id = id
        self.key = key
        self.members = members
        self.client = client
        self.messages = []
        self.offset = offset

    def send_msg(self, message: str):
        signature_bytes = self.client.private_key.sign(message.encode('utf-8'), algo="sha256")
        signature_str = b64encode(signature_bytes).decode('utf-8')
        salt = b64encode(Random.new().read(16)).decode('utf-8')
        content = Payload(self.key, plaintext={"salt": salt,
                                               "sender": self.client.user_id,
                                               "signature": signature_str,
                                               "message": message}).pack()
        content_str = b64encode(content).decode('utf-8')
        self.client.request({'action': Action.SEND_MSG,
                             'content': content_str,
                             'session': self.id})
        self.messages.append(Message(self.members.get(self.client.user_id),
                                     message, signature_str, datetime.now()))

    def decrypt_msg(self, encrypted_content: str, time_sent_str: str) -> Optional[Message]:
        msg_bytes = b64decode(encrypted_content)
        decrypted_content = Payload(self.key, ciphertext=msg_bytes).plaintext
        sender = self.members.get(decrypted_content['sender'])
        assert sender is not None
        verified = sender.pub_key.verify(decrypted_content['message'].encode('utf-8'),
                                         b64decode(decrypted_content['signature']),
                                         algo="sha256")
        time_sent = dateutil.parser.parse(time_sent_str).replace(tzinfo=timezone.utc)
        local_time_sent = time_sent.astimezone()
        assert verified == 1
        return Message(sender,
                       decrypted_content['message'],
                       decrypted_content['signature'],
                       local_time_sent)

    def add_msg(self, encrypted_content: str, time_sent_str: str):
        msg = self.decrypt_msg(encrypted_content, time_sent_str)
        self.messages.append(msg)
        # TODO: notification?

    def get_messages(self):
        [self.add_msg(msg['content'], msg['time_sent']) for msg in self.client.get_messages(self.id)]

    def __str__(self):
        return ", ".join([m.name for m in self.members.values() if m.id != self.client.user_id])


class ChatManager:

    def __init__(self, client: Client):
        sessions = {}
        for session_dict in client.get_sessions():
            session_id = session_dict['id']
            session_key = client.decrypt_session_key(session_dict['key'])
            session_members = {client.user_id: User(client.user_id, client.username, client.pub_key)}
            for member in session_dict['members']:
                member_id = member['id']
                member_name = member['name']
                member_pub_key = Client.load_public_key(member['pub_key'])
                session_members[member_id] = User(member_id, member_name, member_pub_key)
            sessions[session_id] = Session(session_id, session_key, session_members, client)
        self.sessions = sessions

    def add_msg(self, msg_dict: Dict[str, Any], session_id: int):
        session = self.sessions.get(session_id)
        assert session is not None
        session.add_msg(msg_dict['content'], msg_dict['time_sent'])
