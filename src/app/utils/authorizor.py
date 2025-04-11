from flask import request, jsonify, redirect, url_for
from functools import wraps

class UnauthorizedError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

def getUserRole():
    if request.user is None:
        raise UnauthorizedError('User not authenticated')
    if 'role' not in request.user:
        raise UnauthorizedError('User role not found')

    return request.user['role']

def roleRequired(role, isView=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                userRole = getUserRole()
                if userRole != role:
                    if isView:
                        return redirect(url_for('views.index'))
                    return jsonify({'status': False, 'message': 'Unauthorized access'}), 403

                return func(*args, **kwargs)
            except UnauthorizedError as error:
                if isView:
                    return redirect(url_for('views.login'))
                return jsonify({'status': False, 'message': error.message}), 403
            except Exception as error:
                print(f'[ERROR] Error while checking user role: {error}')
                return jsonify({'status': False, 'message': 'Unable to check user\'s role'}), 500
        return wrapper
    return decorator