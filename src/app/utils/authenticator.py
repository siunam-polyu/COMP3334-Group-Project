from flask import request, current_app, jsonify, redirect, url_for, make_response
from datetime import datetime, timedelta
from functools import wraps
from utils.validator import ValidationError
import utils.database
import random
import string
import jwt
import config

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

def setMfaStatus(enableStatus):
    token = request.cookies.get('session')
    if not token:
        raise ValidationError('Unauthorized')

    try:
        payload = verifyJwt(token)
        payload['mfa_enabled'] = enableStatus
        token = signJwt(payload)
        request.user = payload
        return token
    except jwt.ExpiredSignatureError:
        raise ValidationError('Token expired')
    except jwt.InvalidTokenError:
        raise ValidationError('Invalid token')
    except Exception as error:
        print(f'[ERROR] Error while setting MFA status: {error}')
        raise error

def generateMfaCode():
    characters = string.digits
    mfaCode = ''.join(random.choice(characters) for _ in range(config.MFA_CODE_LENGTH))
    return mfaCode

def getMfaVerifyLink(token):
    endpoint = url_for('api.setupMfaSecondStep', _external=True)
    return f'{endpoint}?token={token}'

def isMfaRequired(username):
    try:
        user = utils.database.getUserByUsername(username)
        if not utils.database.isMfaEnabled(user['id']):
            return False
        
        if not utils.database.isMfaPending(user['id']):
            raise ValidationError('No MFA code is available for this user')
        
        return True
    except utils.validator.ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Error while checking MFA requirement: {error}')
        raise error

def verifyJwt(token):
    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=[config.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError as error:
        raise error
    except jwt.InvalidTokenError as error:
        raise error

def signJwt(payload, expireTime=config.JWT_EXPIRE_HOUR):
    payload['exp'] = datetime.now() + timedelta(hours=expireTime)
    return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm=config.JWT_ALGORITHM)

def setLoggedInResponse(user, mfaEnabled=False):
    payload = {
        'id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'mfa_enabled': mfaEnabled,
    }
    token = utils.authenticator.signJwt(payload)
    response = make_response(
        jsonify({'status': True, 'message': 'Logged in successfully'}),
        200
    )
    response.set_cookie('session', token, httponly=True, samesite='Strict')
    return response