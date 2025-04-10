from uuid import uuid4
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