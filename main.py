from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, authenticated
from tornado.escape import json_decode
from tornado.options import parse_command_line
from tornado.httpserver import HTTPServer
from tornado_sqlalchemy import SQLAlchemy, SessionMixin

from settings import COOKIE_SECRET, DATABASE_URL, PORT, ADDRESS
from shema import Url, User
from dashboard import short_generate, hash_function, base_authorization


class ShowUrl(SessionMixin, RequestHandler):
    def get_current_user(self) -> bytes:
        return self.get_secure_cookie('user')

    def _query_up_rating_url(self, url_id) -> None:
        self.session.query(Url).filter(Url.id == url_id).update(
            {'rating': Url.rating + 1}
        )

    def _query_get_url_to_short_url(self, short_url: str):
        url = self.session.query(Url).filter_by(
            abbreviated_address=short_url
        )
        return url.one()

    def _query_get_id_to_username(self, username: str) -> int:
        user_id = self.session.query(User).filter_by(username=username)
        return user_id.one().id

    @authenticated
    def get_authorization(self, url):
        if url.access_level == 'general':
            self.redirect(url.full_address, status=303)
        elif url.access_level == 'private':
            if url.user_id == self._query_get_id_to_username(
                bytes.decode(self.get_current_user())
            ):
                self._query_up_rating_url(url.id)
                self.redirect(url.full_address, status=303)
            else:
                self.set_status(403)
                self.finish({'status': self.get_status(),
                             'error': 'no authorization rights'})

    def get(self):
        if 'url' in self.request.arguments:
            url = self._query_get_url_to_short_url(self.get_argument('url'))
            if url.access_level == 'public':
                self._query_up_rating_url(url.id)
                self.redirect(url.full_address, status=303)
            else:
                self.get_authorization(url)
        else:
            self.set_status(400)
            self.finish({'status': self.get_status(),
                         'error': 'no request parameter'})


class UrlsApp(SessionMixin, RequestHandler):

    def get_current_user(self) -> bytes:
        return self.get_secure_cookie('user')

    def _query_is_unique_short_link(self, short_link: str) -> bool:
        return False if self.session.query(Url).filter_by(
            abbreviated_address=short_link
        ).count() != 0 else True

    def _query_urls_to_user(self, username: str) -> list:
        return self.session.query(Url).filter(
            Url.user_id == self.session.query(User).filter(
                User.username == username
            ).one().id
        ).all()

    def _query_get_url(self, url_id: int):
        return self.session.query(Url).filter_by(
            id=url_id
        ).one()

    def _query_add_url(self, full_url: str, short_url: str,
                       level: str, user=None) -> int:
        add_url = Url(
            full_address=full_url,
            abbreviated_address=short_url,
            access_level=level,
            user_id=user
        )
        self.session.add(add_url)
        self.session.commit()
        return add_url.id

    def access_level(self, request_body: dict) -> tuple:
        if 'access_level' in request_body and \
                request_body['access_level'] in \
                ['public', 'private', 'general']:
            if self.get_current_user():
                return request_body['access_level']
            else:
                return False, \
                       'Authorization is required to change the access level'
        return True, 'public'

    def short_link(self, request_body: dict) -> tuple:
        if 'short_link' in request_body:
            if self._query_is_unique_short_link(request_body['short_link']):
                return request_body['short_link']
            else:
                return False, 'a link exists'
        else:
            short = short_generate(request_body['url'])
            while not self._query_is_unique_short_link(short):
                short = short_generate(request_body['url'])
            return True, short

    @authenticated
    def get(self):
        current_user = bytes.decode(self.get_current_user())
        urls = self._query_urls_to_user(current_user)
        if len(urls) == 0:
            self.set_status(204)
            self.finish({
                'status': self.get_status(),
                'message': 'The Url list is empty'
            })
        else:
            self.set_status(200)
            self.finish({
                'status': self.get_status(),
                'urls': [{
                    'url': url.full_address,
                    'short_url': f'http://{ADDRESS}:{PORT}/'
                                 f'?url={url.abbreviated_address}',
                    'rating': url.rating
                } for url in urls]
            })

    def post(self):
        data = json_decode(self.request.body)
        if 'url' not in data:
            self.set_status(400)
            self.finish({
                'status': self.get_status(),
                'error': 'expected url in json post'
            })
        else:
            short_link = self.short_link(data)
            access_level = self.access_level(data)
            if short_link[0] and access_level[0]:
                linc_id = self._query_add_url(
                    data['url'],
                    self.short_link(data)[1],
                    self.access_level(data)[1],
                    bytes.decode(self.get_current_user())
                )
                url = self._query_get_url(linc_id)
                self.set_status(200)
                self.finish({
                    'status': self.get_status(),
                    'id': linc_id,
                    'short_url': url.abbreviated_address,
                    'access_level': url.access_level
                })
            else:
                self.set_status(400)
                self.finish({'status': self.get_status(),
                             'message': short_link[1] if not short_link[0]
                             else access_level[1]
                             })


class RegistrationApp(SessionMixin, RequestHandler):

    def set_default_headers(self):
        self.set_header("Content-Type", 'application/json; charset="utf-8"')

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
        data = json_decode(self.request.body)
        if 'login' in data and 'password' in data:
            if self._check_login_exists(data['login']):
                hash_password = hash_function(
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
                self.finish({'status': self.get_status(),
                             'error': 'login busy'})
        else:
            self.set_status(400)
            self.finish({'status': self.get_status(),
                         'error': 'request failed'})


class AuthorizationApp(SessionMixin, RequestHandler):

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
                {'status': self.get_status(),
                 'id': 'Not Authorization'}
            )
        else:
            username = bytes.decode(current_user)
            user_id = self._query_one_user_id(User.username == username)
            self.set_status(200)
            self.finish({'status': self.get_status(), 'message': user_id})

    def post(self):
        basic_data = self.request.headers.get('Authorization')
        users_data = base_authorization(basic_data)
        hash_password = hash_function(
            users_data['login'],
            users_data['password']
        )
        user_id = self._query_one_user_id(
            User.username == users_data['login'],
            User.password == hash_password
        )
        if user_id:
            self.set_secure_cookie("user", users_data['login'])
            self.set_status(200)
            self.finish(
                {'status': self.get_status(), 'id': user_id}
            )
        else:
            self.set_status(400)
            self.finish({'status': self.get_status(),
                         'error': 'Invalid login or password'})


class App(Application):
    def __init__(self):
        handlers = [
            (r"/", ShowUrl),
            (r"/urls", UrlsApp),
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
    http_server.bind(port=PORT, address=ADDRESS)
    http_server.start(0)
    IOLoop.instance().start()
