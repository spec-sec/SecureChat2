from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker
from datetime import datetime


engine = create_engine('sqlite:///server.db', echo=True)
Base = declarative_base()


class User(Base):

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    fullname = Column(String)
    password = Column(String)
    last_login = Column(DateTime, default=datetime.utcnow)
    active_key = Column(Integer, ForeignKey("publickey.id"), nullable=True)


class Cookie(Base):

    __tablename__ = 'cookie'

    id = Column(Integer, primary_key=True)
    value = Column(String)
    expires = Column(DateTime)
    user = Column(Integer, ForeignKey("user.id"), nullable=False)


class PublicKey(Base):

    __tablename__ = 'publickey'

    id = Column(Integer, primary_key=True)
    content = Column(String)
    user = Column(Integer, ForeignKey("user.id"), nullable=False)
    date_created = Column(DateTime, default=datetime.utcnow)


class Session(Base):

    __tablename__ = 'session'

    id = Column(Integer, primary_key=True)

    def __repr__(self):
        return "<Session(id='{}')>".format(self.id)


class SessionKey(Base):

    __tablename__ = 'sessionkey'

    id = Column(Integer, primary_key=True)
    content = Column(String)
    user = Column(Integer, ForeignKey("user.id"), nullable=False)
    session = Column(Integer, ForeignKey("session.id"), nullable=True)
    public_key = Column(Integer, ForeignKey("publickey.id"), nullable=True)


class Message(Base):

    __tablename__ = 'message'

    id = Column(Integer, primary_key=True)
    content = Column(String)
    session = Column(Integer, ForeignKey("session.id"), nullable=True)
    time_sent = Column(DateTime, default=datetime.utcnow)


# Base.metadata.create_all(engine)

DBSession = sessionmaker()
DBSession.configure(bind=engine, expire_on_commit=False)
