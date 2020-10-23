from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, authenticated
from tornado.escape import json_decode
from tornado.options import parse_command_line
from tornado.httpserver import HTTPServer
from tornado_sqlalchemy import SQLAlchemy, SessionMixin

from settings import COOKIE_SECRET, DATABASE_URL
from shema import Url, User
from auth import Authorization


class UrlApp(SessionMixin, RequestHandler):
    def set_default_headers(self):
        self.set_header("Content-Type", 'application/json; charset="utf-8"')

    def get_current_user(self):
        return self.get_secure_cookie('user')

    def _query_urls_to_user(self, username: str) -> list:
        return self.session.query(Url).filter(
            Url.user_id == self.session.query(User).filter(
                User.username == username
            ).one().id
        ).all()

    @authenticated
    def get(self):
        current_user = bytes.decode(self.get_current_user())
        urls = self._query_urls_to_user(current_user)
        if len(urls) == 0:
            self.set_status(204)
            self.finish({'status': self.get_status(), 'message': 'The Url list is empty'})


class RegistrationApp(SessionMixin, RequestHandler):

    def _check_login_exists(self, login: str) -> bool:
        result = self.session.query(User).filter_by(username=login)
        if result.count() == 0:
            return True
        return False

    def _create_user(self, login: str, hash_password: str) -> int:
        user = User(username=login, password=hash_password)
        self.session.add(user)
        self.session.commit()
        return user.id

    def post(self):
        self.set_header("Content-Type", "application/json")
        data = json_decode(self.request.body)
        if 'login' in data and 'password' in data:
            if self._check_login_exists(data['login']):
                hash_password = Authorization().hash_function(
                    data['login'], data['password']
                )
                request_user_id = self._create_user(
                    data['login'], hash_password
                )
                self.set_secure_cookie("user", data['login'])
                self.set_status(201)
                self.finish(
                    {'status': self.get_status(), 'id': f'{request_user_id}'}
                )
            else:
                self.set_status(400)
                self.finish({'status': self.get_status(), 'error': 'login busy'})
        else:
            self.set_status(400)
            self.finish({'status': self.get_status(), 'error': 'request failed'})


class AuthorizationApp(SessionMixin, RequestHandler):
    auth = Authorization()

    def get_current_user(self):
        return self.get_secure_cookie('user')

    def _query_one_user_id(self, *args_filter) -> (int, None):
        user = self.session.query(User).filter(*args_filter)
        if user.count() != 0:
            return user.one().id
        return None

    def get(self):
        current_user = self.get_current_user()
        if not current_user:
            self.set_status(401)
            self.finish(
                {'status': self.get_status(), 'id': 'Not Authorization'}
            )
        else:
            username = bytes.decode(current_user)
            user_id = self._query_one_user_id(User.username == username)
            self.set_status(200)
            self.finish({'status': self.get_status(), 'message': user_id})

    def post(self):
        basic_data = self.request.headers.get('Authorization')
        users_data = self.auth.base_auth(basic_data)
        hash_password = self.auth.hash_function(users_data['login'], users_data['password'])
        user_id = self._query_one_user_id(
            User.username == users_data['login'], User.password == hash_password
        )
        if user_id:
            self.set_secure_cookie("user", users_data['login'])
            self.set_status(200)
            self.finish(
                {'status': self.get_status(), 'id': user_id}
            )
        else:
            self.set_status(400)
            self.finish({'status': self.get_status(), 'error': 'Invalid login or password'})


class App(Application):
    def __init__(self):
        handlers = [
            (r"/", UrlApp),
            (r"/registration", RegistrationApp),
            (r"/login", AuthorizationApp)
        ]
        settings = {
            "cookie_secret": COOKIE_SECRET,
            "db": SQLAlchemy(DATABASE_URL),
            "login_url": '/login'
        }
        Application.__init__(self, handlers, **settings)


if __name__ == "__main__":
    parse_command_line()
    http_server = HTTPServer(App())
    http_server.listen(8008)
    IOLoop.instance().start()
