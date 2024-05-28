#!/usr/bin/env python3
""" A module for authentication-related routines"""

import bcrypt
from db import DB
from user import User
import uuid
from typing import Union
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """ Hashing password """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed


def _generate_uuid() -> str:
    """ Generate UUIDs"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database"""

    def __init__(self):
        """Initializes a new Auth instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Register user if Not exist"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """ Credentials validation"""
        user = self._db.find_user_by(email=email)
        if user:
            if bcrypt.checkpw(password.encode(), user.hashed_password):
                return True
        return False

    def create_session(self, email: str) -> str:
        """ Get session ID"""

        user = self._db.find_user_by(email=email)
        if user:
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """ Find user by session IDw"""
        if session_id:
            user = self._db.find_user_by(session_id=session_id)
            if user:
                return user
        return None

    def destroy_session(self, user_id: int) -> None:
        """ Destroy session"""
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """ Generates a password reset token for a user"""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError('No user')

    def update_password(self, reset_token: str, password: str) -> None:
        """ Updates a user's password given the user's reset token"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError('No user')
        new_password_hash = _hash_password(password)
        self._db.update_user(
            user.id, hashed_password=new_password_hash, reset_token=None)
