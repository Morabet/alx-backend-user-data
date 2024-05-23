#!/usr/bin/env python3
""" Session authentication module for the API"""

from api.v1.auth.auth import Auth
import uuid
from models.user import User


class SessionAuth(Auth):
    """ Session authentication class"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ Creates a session id for the user"""
        if user_id is None or type(user_id) != str:
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Retrieves the user id of the user associated with
        a given session id
        """
        if session_id is None or type(session_id) != str:
            return None
        return self.user_id_by_session_id.get(session_id, None)

    def current_user(self, request=None):
        """ Retrieves the user associated with the request"""
        if request is None:
            return None
        return User.get(
            self.user_id_for_session_id(self.session_cookie(request))
        )

    def destroy_session(self, request=None):
        """ Destroys an authenticated session"""
        session_id = self.session_cookie(request)
        if request is None or session_id is None:
            return False
        if self.user_id_for_session_id(session_id) is None:
            return False
        self.user_id_by_session_id.pop(session_id)
        return True
