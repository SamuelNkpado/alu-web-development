#!/usr/bin/env python3
""" Basic authentication module.
"""
import base64
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """ BasicAuth class that inherits from Auth.
    """

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """ Returns the Base64 part of the Authorization header
        for a Basic Authentication.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """ Returns the decoded value of a Base64 string.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            b64_bytes = base64_authorization_header.encode('utf-8')
            decoded_bytes = base64.b64decode(b64_bytes, validate=True)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """ Returns the user email and password from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        res = decoded_base64_authorization_header.split(':', 1)
        return res[0], res[1]

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """ Returns the User instance based on email and password.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        if not users or len(users) == 0:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Overloads Auth.current_user to retrieve User instance from request.
        """
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        b64_header = self.extract_base64_authorization_header(auth_header)
        if b64_header is None:
            return None
        decoded = self.decode_base64_authorization_header(b64_header)
        if decoded is None:
            return None
        email, pwd = self.extract_user_credentials(decoded)
        if email is None or pwd is None:
            return None
        return self.user_object_from_credentials(email, pwd)
