#!/usr/bin/env python3
""" Session authentication with expiration module for the API"""

from api.v1.auth.session_auth import SessionAuth
import os
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """ Session authentication class with expiration"""

    def __init__(self):
        """ Initializes a new SessionExpAuth instance"""
        duration = os.getenv('SESSION_DURATION')
        if duration:
            try:
                self.session_duration = int(duration)
            except ValueError:
                self.session_duration = 0
        else:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """ Creates a session id for the user"""
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        session_dict = {'user_id': user_id, 'created_at': datetime.now()}
        self.user_id_by_session_id[session_id] = session_dict
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Retrieves the user id of the user associated with
        a given session id
        """
        if session_id is None:
            return None
        session_dict = self.user_id_by_session_id.get(session_id)
        if session_dict is None:
            return None
        if self.session_duration <= 0:
            return session_dict.get("user_id")

        session_created = session_dict.get('created_at')
        if session_created is None:
            return None
        expiration_time = session_created + \
            timedelta(seconds=self.session_duration)
        if expiration_time < datetime.now():
            return None
        return session_dict.get('user_id')
