#!/usr/bin/env python3
"""A simple end-to-end (E2E) integration test for `app.py`"""

import requests

BASE_URL = 'http://127.0.0.1:5000'


def register_user(email: str, password: str) -> None:
    """ Tests registering a user"""
    url = f"{BASE_URL}/users"
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}
    response = requests.post(url, data=data)
    assert response.status_code == 400
    assert response.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """ Tests logging in with a wrong password"""
    url = f"{BASE_URL}/sessions"
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    assert response.status_code == 401


def profile_unlogged() -> None:
    """ Tests retrieving profile information whilst logged out"""
    url = f"{BASE_URL}/profile"
    response = requests.get(url)
    assert response.status_code == 403


def log_in(email: str, password: str) -> str:
    """ Tests logging in"""
    url = f"{BASE_URL}/sessions"
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json() == {'email': email, 'message': 'logged in'}
    assert 'session_id' in response.cookies
    return response.cookies.get('session_id')


def profile_logged(session_id: str) -> None:
    """ Tests retrieving profile information whilst logged in"""
    url = f"{BASE_URL}/profile"
    cookies = {"session_id": session_id}
    response = requests.get(url, cookies=cookies)
    assert response.status_code == 200
    assert "email" in response.json()
    assert response.json() == {"email": EMAIL}


def log_out(session_id: str) -> None:
    """ Tests logging out of a session"""
    url = f"{BASE_URL}/sessions"
    cookies = {"session_id": session_id}
    response = requests.delete(url, cookies=cookies, allow_redirects=True)
    assert response.status_code == 200
    assert response.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """ Tests requesting a password reset"""
    url = f"{BASE_URL}/reset_password"
    data = {"email": email}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    return response.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """ Tests updating a user's password"""
    url = f"{BASE_URL}/reset_password"
    data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
