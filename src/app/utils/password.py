import bcrypt
import hmac
import random
import string

def verifyBcryptHash(password, hash):
    # return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))
    passwordHashWithCorrectHashAsSalt = generateBcryptHash(password, hash)
    isSameHash = hmac.compare_digest(passwordHashWithCorrectHashAsSalt, hash)
    return isSameHash

def generateBcryptHash(password, salt=bcrypt.gensalt()):
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# for initialize admin user only
def generatePassword(length=8):
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = string.punctuation
    characterSet = uppercase + lowercase + digits + special_chars

    password = (
        random.choice(uppercase) +
        random.choice(lowercase) +
        random.choice(digits) +
        random.choice(special_chars)
    )
    
    while len(password) < length or not any(c in password for c in uppercase) or not any(c in password for c in lowercase) or not any(c in password for c in digits) or not any(c in password for c in special_chars):
        password += random.choice(characterSet)
    
    return ''.join(random.sample(password, len(password)))