#!/usr/bin/env python3
'''Encrypting passwords'''

import bcrypt


def hash_password(password: str) -> bytes:
    '''hashing the password'''

    bytes_pass = password.encode('utf-8')
    hash = bcrypt.hashpw(bytes_pass, bcrypt.gensalt())

    return hash


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''check if a hashed password is valid'''

    return bcrypt.checkpw(password.encode(), hashed_password)
