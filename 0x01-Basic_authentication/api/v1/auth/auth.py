#!/usr/bin/env python3
""" Authentication module for the API"""

from flask import request
from typing import List, TypeVar


class Auth():
    """ Authentication class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Checks if a path requires authentication"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            path += "/"

        if path in excluded_paths:
            return False
        for excluded_path in excluded_paths:
            if excluded_path.find('*') != -1:
                start_len = excluded_path.find('*')
                if path[:start_len] == excluded_path[:start_len]:
                    return False
                return True
        return True

    def authorization_header(self, request=None) -> str:
        """ Gets the authorization header field from the request"""
        if request is None:
            return None

        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None

        return auth_header

    def current_user(self, request=None) -> TypeVar('User'):
        """ Gets the current user from the request"""

        return None
