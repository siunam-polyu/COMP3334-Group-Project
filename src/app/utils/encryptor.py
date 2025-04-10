from cryptography.fernet import Fernet

def generateEncryptionKey():
    return Fernet.generate_key()