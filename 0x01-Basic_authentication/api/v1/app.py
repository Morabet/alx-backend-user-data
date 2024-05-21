#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
# Initialize auth to None
auth = None

# Determine the AUTH_TYPE from environment variable
auth_type = os.getenv('AUTH_TYPE')

if auth_type == 'auth':
    auth = Auth()

if auth_type == 'basic_auth':
    auth = BasicAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app_views.errorhandler(401)
def unauthorized_error_handler(error):
    """ Custom error handler for 401 Unauthorized """
    return jsonify({"error": "Unauthorized"}), 401


@app_views.errorhandler(403)
def forbidden_error_handler(error):
    """ Custom error handler for 403 Forbidden """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def before_request_func():
    """ Authenticates a user before processing a request"""
    path = request.path
    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/', '/api/v1/forbidden/']
    if auth is None or path not in excluded_paths:
        if auth.require_auth(path, excluded_paths):
            if auth.authorization_header(request) is None:
                abort(401)
            if auth.current_user(request) is None:
                abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
