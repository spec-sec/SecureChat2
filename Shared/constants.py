DEFAULT_PORT = 39483
MODE_SIZE = 1
LENGTH_SIZE = 3


class ClientMode:

    DH = 0
    REQUEST = 1
    LISTEN = 2


class Action:

    CREATE_SESSION = "create_session"
    SEND_MSG = "send_msg"
    LOGIN = "login"
    CREATE_ACCOUNT = "create_account"
    GET_SESSION_KEY = "get_shared_key"
    GET_PUBLIC_KEY = "get_public_key"
    SET_KEY = "set_key"
    GET_SESSIONS = "get_sessions"
    GET_MESSAGES = "get_messages"
    GET_USERNAME = "get_username"
