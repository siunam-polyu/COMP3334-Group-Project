import re

BCRYPT_TRUNCATION_LENGTH = 72
FILENAME_PATTERN = re.compile(r'^[\w\-_. ]+$')

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