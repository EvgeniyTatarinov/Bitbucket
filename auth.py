import jwt
import base64
from datetime import datetime, timedelta
from functools import wraps
from hashlib import sha256 as hashfunction

from tornado.web import RequestHandler

from settings import COOKIE_SECRET, TOKEN_LIFETIME


class JWTToken:
    def __init__(self):
        self.algorithm = 'HS256'

    def jwt_encode(self, user_id: int, login: str) -> dict:
        return jwt.encode(
            {
                "some": {
                    "id": user_id,
                    "login": login
                },
                'exp': datetime.utcnow() + timedelta(seconds=TOKEN_LIFETIME)
            }, COOKIE_SECRET, algorithm=self.algorithm)

    def jwt_decode(self, encoded_jwt):
        # Декодируем jwt, что бы получился словарик
        try:
            data = jwt.decode(encoded_jwt, COOKIE_SECRET, algorithms=[self.algorithm])
            print(data)
            return data['some']
        except jwt.ExpiredSignatureError:
            return False
        except jwt.exceptions.DecodeError:
            return False


class Authorization:

    @staticmethod
    def hash_function(login: str, password: str) -> str:
        encoded = (login + ':' + password).encode()
        result = hashfunction(encoded).hexdigest()
        return result

    # def required(self, function) -> object:
    #     @wraps(function)
    #     def wrapper(*args, **kwargs):
    #         try:
    #             token = self.get_cookie('Token')
    #             user = self.jwt.jwt_decode(token)
    #             if user:
    #                 current_user = user
    #             else:
    #                 return {"status": "ERROR", "message": "Please log in"}
    #         except KeyError as error:
    #             print(error)
    #             return {"status": "ERROR", "message": "no token"}
    #         kwargs['current_user'] = current_user
    #         return function(*args, **kwargs)
    #     return wrapper
    #
    # def optional(self, f):
    #     @wraps(f)
    #     def wrapper(*args, **kwargs):
    #         try:
    #             token = self.get_cookie('Token')
    #             if token is not None:
    #                 print(token)
    #                 user = self.jwt.jwt_decode(token)
    #                 if user:
    #                     current_user = user
    #                 else:
    #                     return f(*args, **kwargs)
    #             else:
    #                 return f(*args, **kwargs)
    #         except KeyError as e:
    #             return f(*args, **kwargs)
    #         kwargs['current_user'] = current_user
    #         return f(*args, **kwargs)
    #     return wrapper

    def base_auth(self, data_authentication_base64):
        """
        Возвращает пару Логин / Пароль при Basic http authentication
        :param data_authentication_base64: request.headers.get('Authorization')
        :return: type(dict) {login: login, password: password}
        """
        a = data_authentication_base64.replace('Basic ', '').encode('UTF-8')
        authorization = base64.b64decode(a).decode("UTF-8").split(':')
        return {"login": authorization[0], "password": authorization[1]}
