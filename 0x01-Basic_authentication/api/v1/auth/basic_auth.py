#!/usr/bin/env python3
""" Basic authentication module for the API"""

from flask import request
from typing import List, TypeVar
from api.v1.auth.auth import Auth
import base64
from models.user import User


class BasicAuth(Auth):
    """ Basic authentication class"""

    def extract_base64_authorization_header(
            self, authorization_header: str
    ) -> str:
        """ Extracts the Base64 part of the Authorization header
        for a Basic Authentication"""

        if authorization_header and type(authorization_header) == str:
            if authorization_header.startswith("Basic ", 0):
                return authorization_header[6:]
        return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str
    ) -> str:
        """ Decodes a base64-encoded authorization header"""

        if base64_authorization_header and \
                type(base64_authorization_header) == str:
            try:
                decode_bytes = base64.b64decode(base64_authorization_header)
                decode_str = decode_bytes.decode()
                return decode_str
            except Exception:
                return None

        return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """ Extracts user credentials from a base64-decoded authorization
        header that uses the Basic authentication flow"""

        if decoded_base64_authorization_header and \
                type(decoded_base64_authorization_header) == str:
            if ":" in decoded_base64_authorization_header:
                email, pas = decoded_base64_authorization_header.split(":", 1)
                return (email, pas)

        return (None, None)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """ Retrieves a user based on the user's authentication credentials"""

        if user_email is None or type(user_email) != str:
            return None
        if user_pwd is None or type(user_pwd) != str:
            return None
        try:
            users = User.search({"email": user_email})

            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
        except KeyError:
            return None
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves the user from a request"""
        Authorization = self.authorization_header(request)
        base64 = self.extract_base64_authorization_header(Authorization)
        decode = self.decode_base64_authorization_header(base64)
        credentials = self.extract_user_credentials(decode)
        if credentials:
            return self.user_object_from_credentials(
                credentials[0], credentials[1]
            )
