import socket
import threading
import sys
from sqlalchemy.orm.exc import NoResultFound
from M2Crypto import DH as M2DH
from Shared.constants import *
from Shared.constants import Action
from Shared.dhke import DH
from Shared.encrypted_socket import EncryptedSocket
from Server.database import *
from Server.user import login, verify_cookie, create_user, AuthenticationError
from Server.session import create_session
from Server.message import create_message
from typing import Dict, List, Optional
import json


BACKLOG = 5

# IMPORTANT! Small key size for development ONLY!
DH_SIZE = 512


class Client(EncryptedSocket):

    def __init__(self, connection: socket.socket, address: str, dh_params: M2DH.DH, user=None):

        super().__init__(connection)
        self.address = address
        self.user = user
        self.dh_params = dh_params
        self.key = self.dh()

    def dh(self):
        """
        Perform Diffie-Hellman Key Exchange with a client.
        :return shared_key: shared encryption key for AES
        """
        # p: shared prime
        p = DH.b2i(self.dh_params.p)
        # g: primitive root modulo
        g = DH.b2i(self.dh_params.g)
        # a: randomized private key
        a = DH.gen_private_key()
        # Generate public key from p, g, and a
        public_key = DH.gen_public_key(g, a, p)
        # Create a DH message to send to client as bytes
        payload = DH(p, g, public_key).__dict__()
        self.send(payload, ClientMode.DH)
        # Receive public key from client as bytes
        mode, payload_data = self.process_packet()
        client_key = json.loads(payload_data.decode('utf-8'))['key']
        # Calculate shared key with newly received client key
        shared_key = DH.get_shared_key(client_key, a, p)
        return shared_key

    def authenticate(self, username: str, password: str) -> Cookie:
        self.user, cookie = login(username, password)
        return cookie


class Server:

    def __init__(self, host='127.0.0.1', port=DEFAULT_PORT):

        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dh_params = M2DH.gen_params(DH_SIZE, 2)
        self.clients = {}

        try:
            self.start()
        except KeyboardInterrupt:
            [cl.connection.close() for cl in list(self.clients.values())]
            self.socket.close()
            sys.exit()

    def start(self):

        self.socket.bind((self.host, self.port))
        self.socket.listen(BACKLOG)

        while True:
            connection, address = self.socket.accept()
            client = Client(connection, address, self.dh_params)
            threading.Thread(target=self.listen, args=(client,)).start()

    def listen(self, client: Client):
        # Handle payload depending on mode
        try:
            mode, payload_data = client.process_packet()
        except ConnectionError:
            # TODO: Connection Error Message
            if client.user.id is not None:
                self.clients.pop(client.user.id, None)
            print(self.clients)
            return
        print("Incoming packet!")
        print("Mode: {}".format(mode))
        assert client.key is not None
        payload = client.decrypt_payload_data(payload_data)
        print("Payload: {}".format(payload))
        if mode == ClientMode.REQUEST:
            response = RequestHandler(client, self, payload).response
            client.send(response, ClientMode.REQUEST)
            client.connection.close()
        elif mode == ClientMode.LISTEN:
            client.user = verify_cookie(payload['cookie'])
            self.clients[client.user.id] = client
            print(self.clients)
        return


class RequestHandler:

    def __init__(self, client: Client, server: Server, payload: Dict):
        self.client = client
        self.server = server
        self.payload = payload
        self.db_session = DBSession()
        self.response = self.gen_response()
        self.db_session.close()

    def gen_response(self) -> Dict:
        action = self.payload.get('action')

        if action is None:
            return {'errors': 'An action must be declared'}

        # Log in actions (must come first)
        if action == Action.LOGIN:
            return self.login()
        elif action == Action.CREATE_ACCOUNT:
            return self.create_account()
        else:
            try:
                self.client.user = verify_cookie(self.payload['cookie'])
            except KeyError:
                return {"errors": "You must log in first"}
            except AuthenticationError:
                return {"errors": "Invalid cookie"}

        if action == Action.SET_KEY:
            return self.set_key()
        elif action == Action.GET_SESSIONS:
            return self.get_sessions()
        elif action == Action.GET_PUBLIC_KEY:
            return self.get_public_key()
        elif action == Action.GET_SESSION_KEY:
            return self.get_session_key()
        elif action == Action.CREATE_SESSION:
            return self.create_session()
        elif action == Action.GET_USERNAME:
            return self.get_username()
        elif action == Action.GET_MESSAGES:
            return self.get_messages()
        elif action == Action.SEND_MSG:
            return self.send_msg()
        else:
            return {'errors': 'Invalid action'}

    def get_field_errors(self, action_dict: List) -> Optional[Dict]:
        missing_fields = self.get_missing_fields(action_dict)
        if len(missing_fields) == 0:
            return None
        else:
            return {"errors": "The following fields must be declared: {}".format(", ".join(missing_fields))}

    def get_missing_fields(self, action_dict: List) -> List:
        payload_keys = list(self.payload.keys())
        missing_fields = []
        for key in action_dict:
            if key not in payload_keys:
                missing_fields.append(key)
        return missing_fields

    def login(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.LOGIN)
        if field_errors is not None:
            return field_errors
        try:
            cookie = self.client.authenticate(self.payload['username'], self.payload['password'])
        except AuthenticationError:
            return {'errors': 'Invalid username or password'}
        return {'id': self.client.user.id, 'cookie': cookie.value}

    def create_account(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.CREATE_ACCOUNT)
        if field_errors is not None:
            return field_errors
        try:
            new_user = create_user(self.payload['username'], self.payload['password'],
                                   fullname=self.payload['fullname'])
        except ValueError:
            return {'errors': 'Username taken'}
        cookie = self.client.authenticate(self.payload['username'], self.payload['password'])
        return {'id': self.client.user.id, 'cookie': cookie.value}

    def set_key(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.SET_KEY)
        if field_errors is not None:
            return field_errors
        new_pk = PublicKey(content=self.payload['content'], user=self.client.user.id)
        self.db_session.add(new_pk)
        self.db_session.flush()
        current_user = self.db_session.query(User).filter_by(id=self.client.user.id).one()
        current_user.active_key = new_pk.id
        self.db_session.commit()
        return {'key': new_pk.id}

    def get_sessions(self) -> Dict:
        sessions = []
        user_session_keys = self.db_session.query(SessionKey).filter_by(user=self.client.user.id).all()
        for skey in user_session_keys:
            session = skey.session
            recipient_skeys = self.db_session.query(SessionKey).filter_by(session=session).\
                filter(SessionKey.user != self.client.user.id).all()
            recipients = []
            for r_skey in recipient_skeys:
                recipient = self.db_session.query(User).filter_by(id=r_skey.user).one()
                recipients.append({'id': recipient.id,
                                   'name': recipient.name,
                                   'pub_key': self.db_session.query(PublicKey).filter_by(id=recipient.active_key).one().content})
            sessions.append({'id': session, 'key': skey.content, 'members': recipients})
        print(sessions)
        return {'sessions': sessions}

    def get_public_key(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.GET_PUBLIC_KEY)
        if field_errors is not None:
            return field_errors
        print(self.payload)
        desired_user = self.db_session.query(User).filter_by(id=self.payload['user']).one()
        active_key = self.db_session.query(PublicKey).filter_by(id=desired_user.active_key).one()
        return {'public_key': active_key.content}

    def get_session_key(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.GET_SESSION_KEY)
        if field_errors is not None:
            return field_errors
        try:
            msg_session = self.db_session.query(Session).filter_by(id=self.payload['session']).one()
        except NoResultFound:
            return {'errors': 'Session not found'}
        try:
            session_key = self.db_session.query(SessionKey).filter_by(session=msg_session.id,
                                                                      user=self.client.user.id).one()
        except NoResultFound:
            return {'errors': 'Session key not found'}
        return {'session_key': session_key.content}

    def create_session(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.CREATE_SESSION)
        if field_errors is not None:
            return field_errors
        parsed_members = []
        for user_id, key in self.payload['members']:
            try:
                user = self.db_session.query(User).filter_by(id=user_id).one()
            except NoResultFound:
                # TODO: keep track of missing users
                continue
            parsed_members.append((user, key))
        chat_session = create_session(parsed_members)
        return {'session': chat_session.id}

    def get_messages(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.GET_MESSAGES)
        if field_errors is not None:
            return field_errors
        print(self.payload)
        user_in_session = self.db_session.query(SessionKey).filter_by(session=self.payload['session'],
                                                                      user=self.client.user.id).count() != 0
        if not user_in_session:
            print("User not in session!")
            return {'errors': 'You are not a member of this session'}
        messages = self.db_session.query(Message).filter_by(session=self.payload['session']).all()
        return {'messages': [{'content': m.content,
                              'time_sent': m.time_sent.isoformat()} for m in messages]}

    def get_username(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.GET_USERNAME)
        if field_errors is not None:
            return field_errors
        try:
            user = self.db_session.query(User).filter_by(id=self.payload['user']).one()
        except NoResultFound:
            return {'errors': 'User not found'}
        return {'name': user.name}

    def send_msg(self) -> Dict:
        field_errors = self.get_field_errors(ActionDicts.SEND_MSG)
        if field_errors is not None:
            return field_errors
        try:
            msg_session = self.db_session.query(Session).filter_by(id=self.payload['session']).one()
        except NoResultFound:
            return {'errors': 'Session not found'}
        keys = self.db_session.query(SessionKey).filter_by(session=msg_session.id).all()
        user_in_session = self.client.user.id in [k.user for k in keys]
        if not user_in_session:
            return {'errors': 'You are not a member of this session'}
        message = create_message(self.payload['content'], msg_session)
        for key in keys:
            if key.user == self.client.user.id:
                # skip the user who sent it
                continue
            recipient = self.server.clients.get(key.user)
            if recipient is not None:
                recipient.send({'type': 'message',
                                'session': msg_session.id,
                                'id': message.id,
                                'content': message.content,
                                'time_sent': message.time_sent.isoformat()},
                               ClientMode.LISTEN)
        return {'message': message.id}


class ActionDicts:

    CREATE_SESSION = ['members']
    SEND_MSG = ['content', 'session']
    LOGIN = ['username', 'password']
    CREATE_ACCOUNT = ['username', 'fullname', 'password']
    GET_SESSION_KEY = ['session']
    GET_PUBLIC_KEY = ['user']
    SET_KEY = ['content']
    GET_MESSAGES = ['session']
    GET_USERNAME = ['user']
