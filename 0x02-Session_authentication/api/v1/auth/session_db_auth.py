#!/usr/bin/env python3
""" Session authentication with expiration
and storage support module for the API
"""

from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from datetime import datetime, timedelta


class SessionDBAuth(SessionExpAuth):
    """ Session authentication class with expiration and storage support"""

    def __init__(self):
        """ Initializes """
        super().__init__()
        self.user_session = UserSession()
        self.user_session.load_from_file()

    def create_session(self, user_id=None):
        """ Creates a new session and stores it in the database"""
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        user_session = UserSession(user_id=user_id, session_id=session_id)
        user_session.save()

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Retrieves the user ID associated with a given session ID"""
        if session_id is None:
            return None

        users_session = UserSession.search({"session_id": session_id})
        if not users_session:
            return None
        expiration_time = users_session[0].created_at + \
            timedelta(seconds=self.session_duration)
        if expiration_time < datetime.now():
            return None
        return users_session[0].user_id

    def destroy_session(self, request=None):
        """ Destroys an authenticated session"""
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        users_session = UserSession.search({"session_id": session_id})
        if not users_session:
            return False
        users_session[0].remove()
        return True
