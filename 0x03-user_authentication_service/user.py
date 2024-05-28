#!/usr/bin/env python3
""" The `user` model's module"""

from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """ User model """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __init__(self, *args, **kwargs) -> None:
        """ Initialize a new User instance """
        if kwargs:
            for key, value in kwargs.items():
                setattr(self, key, value)
