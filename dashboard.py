import base64
from hashlib import sha256 as hashfunction

from settings import LINK_LENGTH


def short_generate(url):
    return hashfunction(url).hexdigest()[:LINK_LENGTH]


def hash_function(login: str, password: str) -> str:
    encoded = (login + ':' + password).encode()
    result = hashfunction(encoded).hexdigest()
    return result


def base_authorization(data_authentication_base64: str) -> dict:
    """
    Возвращает пару Логин / Пароль при Basic http authentication
    :param data_authentication_base64: request.headers.get('Authorization')
    :return: type(dict) {login: login, password: password}
    """
    a = data_authentication_base64.replace('Basic ', '').encode('UTF-8')
    authorization = base64.b64decode(a).decode("UTF-8").split(':')
    return {"login": authorization[0], "password": authorization[1]}
