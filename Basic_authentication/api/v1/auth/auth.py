#!/usr/bin/env python3
""" API authentication module.
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """ Auth class to manage API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Method that defines if a path requires authentication.
        """
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        if not path.endswith('/'):
            path += '/'

        for excluded_path in excluded_paths:
            if not excluded_path.endswith('/'):
                if path == excluded_path + '/':
                    return False
            else:
                if path == excluded_path:
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Method that gets the Authorization header from request.
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Method that returns current User instance.
        """
        return None
