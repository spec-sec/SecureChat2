from Server.database import DBSession, Session, SessionKey, User
from typing import Tuple, List


# TODO: pass in db_session instead of creating new one

def create_session(members: List[Tuple[User, str]]):

    db_session = DBSession()
    chat_session = Session()
    db_session.add(chat_session)
    db_session.flush()

    for user, key in members:
        db_session.add(SessionKey(content=key,
                                  user=user.id,
                                  session=chat_session.id,
                                  public_key=user.active_key))

    db_session.commit()
    db_session.close()

    return chat_session
