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
        print(f'[ERROR] Encryption failed: {error}')
        raise error
    
def decryptFile(userId, encryptedData, fileId=str()):
    try:
        userEncryptionKey = utils.database.getUserEncryptionKey(userId, fileId)
        fernet = Fernet(userEncryptionKey)
        return fernet.decrypt(encryptedData).decode('utf-8')
    except Exception as error:
        print(f'[ERROR] Decryption failed: {error}')
        raise error