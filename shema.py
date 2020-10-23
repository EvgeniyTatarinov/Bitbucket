from sqlalchemy import Column, String, BigInteger, ForeignKey
from tornado_sqlalchemy import SQLAlchemy

from settings import DATABASE_URL


db = SQLAlchemy(url=DATABASE_URL)


class User(db.Model):
    __tablename__ = 'user'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True)
    password = Column(String(255))

    def __init__(self, username, password):
        self.username = username
        self.password = password


class Url(db.Model):
    __tablename__ = 'url'
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    full_address = Column(String(255))
    abbreviated_address = Column(String(255), unique=True)
    access_level = Column(String(10), default='general')
    rating = Column(BigInteger, default=0)
    user_id = Column('user_id', BigInteger, ForeignKey('user.id'))

    def __init__(self, full_address, abbreviated_address, access_level, user_id):
        self.full_address = full_address
        self.abbreviated_address = abbreviated_address
        self.access_level = access_level
        self.user_id = user_id
