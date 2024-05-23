#!/usr/bin/env python3
""" Module of session authenticating views"""

from flask import jsonify, abort, request, make_response
from api.v1.views import app_views
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login_user():
    """ JSON representation of a User object"""

    email = request.form.get('email')
    password = request.form.get('password')
    if email is None or email == '':
        return jsonify({"error": "email missing"}), 400
    if password is None or password == '':
        return jsonify({"error": "password missing"}), 400

    users = User.search({"email": email})
    if users == []:
        return jsonify({"error": "no user found for this email"}), 404
    valid_user = None
    for user in users:
        if user.is_valid_password(password):
            valid_user = user
            break
    if valid_user is None:
        return jsonify({"error": "wrong password"}), 401
    from api.v1.app import auth
    session_id = auth.create_session(valid_user.id)
    response = make_response(jsonify(valid_user.to_json()))
    _my_session_id = os.getenv('SESSION_NAME')
    if _my_session_id:
        response.set_cookie(_my_session_id, session_id)

    return response


@app_views.route(
    '/auth_session/logout', methods=['DELETE'], strict_slashes=False
)
def logout():
    """  An empty JSON object """
    from api.v1.app import auth
    is_destroyed = auth.destroy_session(request)
    if not is_destroyed:
        abort(404)

    return jsonify({}), 200
