import utils.database
from cryptography.fernet import Fernet

def generateEncryptionKey():
    return Fernet.generate_key()

def encryptFile(userId, data):
    try:
        userEncryptionKey = utils.database.getUserEncryptionKey(userId)
        fernet = Fernet(userEncryptionKey)
        return fernet.encrypt(data)
    except Exception as error:
        print(f'Encryption failed: {error}')
        raise error