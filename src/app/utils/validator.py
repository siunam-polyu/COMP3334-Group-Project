from flask import request
from email.utils import parseaddr
import re
import config
import utils.authenticator

BCRYPT_TRUNCATION_LENGTH = 72
UUIDV4_LENGTH = 36
FILENAME_PATTERN = re.compile(r'^[\w\-_. ]+$')
HEX_PATTERN = re.compile(r'[0-9a-f]+')

class ValidationError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

def validateUsername(username):
    if not username:
        raise ValidationError('Username cannot be empty')
    if len(username) < 3 or len(username) > 20:
        raise ValidationError('Username must be between 3 and 20 characters')
    if not username.isalnum():
        raise ValidationError('Username can only contain letters and numbers')
    if username[0].isdigit():
        raise ValidationError('Username cannot start with a number')
    
    return True

def validatePassword(password):
    if not password:
        raise ValidationError('Password cannot be empty')
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long')
    if len(password) > BCRYPT_TRUNCATION_LENGTH: # avoid bcrypt truncation
        raise ValidationError('Password must be at most 72 characters long')
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    isPasswordStrong = has_upper and has_lower and has_digit and has_special
    if not isPasswordStrong:
        raise ValidationError('Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character')
    
    return isPasswordStrong

def validateNewPassword(currentPassword, newPassword, confirmNewPassword):
    try:
        validatePassword(newPassword)
        validatePassword(confirmNewPassword)
        
        if newPassword != confirmNewPassword:
            raise ValidationError('New password and confirmation password do not match')
        if currentPassword == newPassword:
            raise ValidationError('New password cannot be the same as the current password')
    except ValidationError as error:
        raise error
    
    return True

def validateFilename(filename):
    if not filename:
        raise ValidationError('Filename cannot be empty')
    if len(filename) < 3:
        raise ValidationError('Filename must be at least 3 characters long')
    if len(filename) > 255:
        raise ValidationError('Filename cannot exceed 255 characters')
    if not FILENAME_PATTERN.match(filename):
        raise ValidationError('Filename can only contain letters, numbers, dashes, underscores, and spaces')
    
    return True

def validateFileId(fileId):
    if not fileId:
        raise ValidationError('File ID cannot be empty')
    if not isinstance(fileId, str):
        raise ValidationError('File ID must be a string')
    if len(fileId) != UUIDV4_LENGTH:
        raise ValidationError('Invalid File ID format')
    
    return True

def validateUserId(userId):
    if not userId:
        raise ValidationError('User ID cannot be empty')
    if not isinstance(userId, str):
        raise ValidationError('User ID must be a string')
    if len(userId) != UUIDV4_LENGTH:
        raise ValidationError('Invalid User ID format')
    
    return True

def validateMfaCode(mfaCode):
    if not mfaCode:
        raise ValidationError('MFA code cannot be empty')
    if not isinstance(mfaCode, str):
        raise ValidationError('MFA code must be a string')
    if len(mfaCode) != config.MFA_CODE_LENGTH:
        raise ValidationError(f'MFA code must be {config.MFA_CODE_LENGTH} characters long')
    
    if not mfaCode.isdigit():
        raise ValidationError('MFA code must contain only digits')
    
    return True

def validateRegisterForm(username, password):
    try:
        validateUsername(username)
        validatePassword(password)
        
        return True
    except Exception as error:
        raise error
    except ValidationError as error:
        raise error
    
def validateLoginForm(username, password):
    try:
        validateUsername(username)
        validatePassword(password)

        return True
    except ValidationError as error:
        raise error

def validatePasswordResetForm(currentPassword, newPassword, confirmNewPassword):
    try:
        validatePassword(currentPassword)
        validateNewPassword(currentPassword, newPassword, confirmNewPassword)

        return True
    except ValidationError as error:
        raise error

def validateFileUploadForm(files):
    try:
        if 'file' not in files:
            raise ValidationError('No file provided')
        
        file = files['file']
        filename = file.filename
        validateFilename(filename)
    except ValidationError as error:
        raise error

def validateFileDownloadForm(fileId):
    try:
        validateFileId(fileId)
        
        return True
    except ValidationError as error:
        raise error
    
def validateShareFileForm(fileId, shareWithUsername):
    try:
        validateFileId(fileId)
        validateUsername(shareWithUsername)
        if shareWithUsername == request.user['username']:
            raise ValidationError('Cannot share file with yourself')
        
        return True
    except ValidationError as error:
        raise error
    
def validateMfaSetupFirstStepForm(email):
    try:
        if utils.database.isMfaEnabled(request.user['id']):
            raise ValidationError('MFA is already enabled')
        
        if not email:
            raise ValidationError('Email cannot be empty')
        if not isinstance(email, str):
            raise ValidationError('Email must be a string')
        if len(email) > 255:
            raise ValidationError('Email cannot exceed 255 characters')
        
        parseaddr(email)        
        return True
    except ValidationError as error:
        raise error
    except Exception as error:
        raise ValidationError('Invalid email address format')
    
def validateMfaSetupSecondStepForm(token):
    try:
        if utils.database.isMfaEnabled(request.user['id']):
            raise ValidationError('MFA is already enabled')
        
        if not token:
            raise ValidationError('Token cannot be empty')
        if not isinstance(token, str):
            raise ValidationError('Token must be a string')
        if len(token) != (config.MFA_VERIFY_TOKEN_LENGTH * 2):
            raise ValidationError(f'Token must be {(config.MFA_VERIFY_TOKEN_LENGTH * 2)} characters long')
        
        if not HEX_PATTERN.match(token):
            raise ValidationError('Token must contain only hexadecimal characters')
        
        return True
    except ValidationError as error:
        raise error
    
def validateMfaRequest(username):
    try:
        validateUsername(username)
        if not utils.authenticator.isMfaRequired(username):
            raise ValidationError('MFA is not required for this user')
        
        return True
    except ValidationError as error:
        raise error
    except Exception as error:
        raise ValidationError('Error while validating MFA request')

def validateMfaVerifyForm(username, mfaCode):
    try:
        validateUsername(username)
        validateMfaCode(mfaCode)
        if not utils.authenticator.isMfaRequired(username):
            raise ValidationError('MFA is not required for this user')
        
        return True
    except ValidationError as error:
        raise error
    except Exception as error:
        raise ValidationError('Error while validating MFA verification form')