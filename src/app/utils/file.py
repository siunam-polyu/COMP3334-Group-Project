from uuid import uuid4
from utils.validator import ValidationError
import os.path
import utils.database
import utils.encryptor

UPLOAD_PATH = './uploads'

def upload(userId, file):
    try:
        fileId = str(uuid4())
        originalFilename = os.path.basename(file.filename)
        filename = f'{str(uuid4())}.encrypted'
        utils.database.insertFileRecord(fileId, userId, filename, originalFilename)

        encryptedData = utils.encryptor.encryptFile(userId, file.read())
        uploadPath = os.path.join(UPLOAD_PATH, filename)
        with open(uploadPath, 'wb') as encryptedFile:
            encryptedFile.write(encryptedData)

        return fileId
    except Exception as error:
        print(f'[ERROR] Unable to upload file: {error}')
        raise error
    
def read(userId, fileId):
    try:
        fileRecord = utils.database.getUploadedOrSharedFileRecord(fileId, userId)
        uploadPath = os.path.join(UPLOAD_PATH, fileRecord['filename'])

        with open(uploadPath, 'rb') as encryptedFile:
            encryptedData = encryptedFile.read()

        decryptedData = utils.encryptor.decryptFile(userId, encryptedData, fileId)
        return { 'filename': fileRecord['original_filename'], 'data': decryptedData }
    except ValidationError as error:
        print(f'[ERROR] Validation error: {error}')
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to read file: {error}')
        raise error
    
def delete(userId, fileId):
    try:
        fileRecord = utils.database.getUploadedOrSharedFileRecord(fileId, userId)
        uploadPath = os.path.join(UPLOAD_PATH, fileRecord['filename'])

        os.remove(uploadPath)
        utils.database.deleteFileRecord(fileId, userId)
    except ValidationError as error:
        print(f'[ERROR] Validation error: {error}')
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to delete file: {error}')
        raise error

def createFileVersion(file_id, encrypted_data):
    # conn.execute('''
    #     INSERT INTO file_versions (file_id, encrypted_data, created_at)
    #     VALUES (?, ?, CURRENT_TIMESTAMP)
    # ''', (file_id, encrypted_data))
    # conn.commit()
    pass
