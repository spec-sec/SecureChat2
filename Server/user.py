from Server.database import User, DBSession, Cookie
from sqlalchemy.orm.exc import NoResultFound
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
from os import urandom
from typing import Tuple


# TODO: pass in db_session instead of creating new one


def create_user(name: str, password: str, fullname=""):

    db_session = DBSession()
    name_available = db_session.query(User).filter_by(name=name).count() == 0

    if not name_available:
        db_session.rollback()
        db_session.close()
        raise ValueError('Username already in use')

    db_session.add(User(name=name, fullname=fullname, password=create_password(password)))
    db_session.commit()
    db_session.close()


def create_password(plaintext: str) -> str:

    return pbkdf2_sha256.encrypt(plaintext, rounds=10000, salt_size=16)


def create_cookie() -> str:

    return urandom(32).hex()


def login(username: str, password: str) -> Tuple[User, Cookie]:

    db_session = DBSession()

    try:
        desired_user = db_session.query(User).filter_by(name=username).one()
    except NoResultFound:
        db_session.close()
        raise AuthenticationError()

    if desired_user is None:
        db_session.close()
        raise AuthenticationError()

    if pbkdf2_sha256.verify(password, desired_user.password):
        desired_user.last_login = datetime.utcnow()
        # Delete existing cookies
        db_session.query(Cookie).filter_by(user=desired_user.id).delete()
        print("Existing cookies deleted!")
        # Create new cookie
        cookie = Cookie(value=create_cookie(),
                        user=desired_user.id,
                        expires=datetime.utcnow() + timedelta(days=1))
        print("Cookie created!")
        db_session.add(cookie)
        db_session.commit()
        db_session.close()
        return desired_user, cookie

    else:
        db_session.close()
        raise AuthenticationError()


def verify_cookie(cookie_value: str) -> User:

    db_session = DBSession()

    try:
        desired_cookie = db_session.query(Cookie).filter_by(value=cookie_value).one()
    except NoResultFound:
        db_session.close()
        raise AuthenticationError()

    if desired_cookie is None:
        db_session.close()
        raise AuthenticationError()

    if datetime.utcnow() >= desired_cookie.expires:
        db_session.close()
        raise AuthenticationError

    user = db_session.query(User).filter_by(id=desired_cookie.user).one()
    db_session.close()

    return user


class AuthenticationError(Exception):

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
