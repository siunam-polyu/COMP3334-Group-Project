from flask import request, current_app, jsonify, redirect, url_for
from datetime import datetime, timedelta
from functools import wraps
import jwt

JWT_EXPIRE_HOUR = 24
JWT_ALGORITHM = 'HS256'
MFA_CODE_EXPIRE_MINUTE = 5

def isAuthenticatedWrapper(isView=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.user is not None:
                return func(*args, **kwargs)
            
            token = request.cookies.get('session')
            if not token:
                if isView:
                    return redirect(url_for('views.login'))
                return jsonify({'status': False, 'message': 'Unauthorized'}), 401
            
            try:
                verifyJwt(token)
            except jwt.ExpiredSignatureError:
                if isView:
                    return redirect(url_for('views.login'))
                return jsonify({'status': False, 'message': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                if isView:
                    return redirect(url_for('views.login'))
                return jsonify({'status': False, 'message': 'Invalid token'}), 401
            return func(*args, **kwargs)
        return wrapper
    return decorator

def isNotAuthenticatedWrapper(isView=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.user is None:
                return func(*args, **kwargs)
            
            token = request.cookies.get('session')
            if not token:
                return func(*args, **kwargs)

            try:
                verifyJwt(token)
                if isView:
                    return redirect(url_for('views.index'))
            
                return jsonify({'message': 'You are already authenticated'}), 401
            except jwt.ExpiredSignatureError:
                pass
            except jwt.InvalidTokenError:
                pass
            return func(*args, **kwargs)
        return wrapper
    return decorator

def isAuthenticated():
    token = request.cookies.get('session')
    if not token:
        return False

    try:
        verifyJwt(token)
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False
    return True

def verifyJwt(token):
    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError as error:
        raise error
    except jwt.InvalidTokenError as error:
        raise error

def signJwt(payload, expireTime=JWT_EXPIRE_HOUR):
    payload['exp'] = datetime.now() + timedelta(hours=expireTime)
    return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm=JWT_ALGORITHM)

def getMfaToken(payload):
    return signJwt(payload, MFA_CODE_EXPIRE_MINUTE)