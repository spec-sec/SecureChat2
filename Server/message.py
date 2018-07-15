from Server.database import DBSession, Session, Message


# TODO: pass in db_session instead of creating new one

def create_message(content: str, session: Session):

    db_session = DBSession()
    msg = Message(content=content, session=session.id)
    db_session.add(msg)

    db_session.commit()
    db_session.close()

    return msg
