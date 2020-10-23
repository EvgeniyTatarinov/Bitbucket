import json

from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, HTTPError
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

    def get(self, current_user=None):
        urls_to_user = self.session.query(Url).filter_by(user_id=1)
        print(urls_to_user.all())
        self.write(json.dumps(
            {'status': 200, 'result': f'message {urls_to_user.all()}'}
        ))


class UserApp(SessionMixin, RequestHandler):

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
                self.set_status(200)
                self.finish(
                    {'status': self.get_status(), 'id': f'{request_user_id}'}
                )
            else:
                self.set_status(400)
                self.finish({'status': self.get_status(), 'error': 'login busy'})
        else:
            self.set_status(400)
            self.finish({'status': self.get_status(), 'error': 'request failed'})


class App(Application):
    def __init__(self):
        handlers = [
            (r"/", UrlApp),
            (r"/user", UserApp),
        ]
        settings = {
            "cookie_secret": COOKIE_SECRET,
            "db": SQLAlchemy(DATABASE_URL),
        }
        Application.__init__(self, handlers, **settings)


if __name__ == "__main__":
    parse_command_line()
    http_server = HTTPServer(App())
    http_server.listen(8008)
    IOLoop.instance().start()
