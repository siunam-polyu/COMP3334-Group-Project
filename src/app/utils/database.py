import sqlite3
import utils.authenticator
import utils.password
import utils.encryptor
import utils.mail
import config
from flask import g
from utils.validator import ValidationError
from uuid import uuid4
from datetime import datetime

def initDatabaseWithSchema():
    adminPasswordHash = utils.password.generateBcryptHash(config.ADMIN_PASSWORD)
    encryptionKey = utils.encryptor.generateEncryptionKey()

    try:
        createUserTableQuery = f'''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT CHECK(length(id) = 36) PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            role TEXT DEFAULT '{config.DEFAULT_USER_ROLE}',
            mfa_email TEXT,
            mfa_verify_token TEXT,
            mfa_verify_token_expiry DATETIME,
            mfa_code TEXT,
            mfa_code_expiry DATETIME,
            mfa_enabled BOOLEAN DEFAULT 0,
            last_login DATETIME,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked BOOLEAN DEFAULT 0,
            account_locked_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        '''
        executeQuery(createUserTableQuery)

        createFilesTableQuery = '''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT CHECK(length(id) = 36) PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        );
        '''
        executeQuery(createFilesTableQuery)

        createFileVersionsTableQuery = '''
        CREATE TABLE IF NOT EXISTS file_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            encrypted_data BLOB NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files (id)
        );
        '''
        executeQuery(createFileVersionsTableQuery)

        createSharedFilesTableQuery = '''
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL,
            shared_with_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files (id),
            FOREIGN KEY (shared_with_id) REFERENCES users (id)
        );
        '''
        executeQuery(createSharedFilesTableQuery)

        createAuditLogsTableQuery = '''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        '''
        executeQuery(createAuditLogsTableQuery)

        insertAdminUserQuery = f'''
        INSERT INTO users (id, username, password, encryption_key, role)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET id = ?, password = ?, encryption_key = ?, role = ?;
        '''
        executeQuery(insertAdminUserQuery, (
            config.ADMIN_USER_ID, config.ADMIN_USERNAME, adminPasswordHash, encryptionKey, config.ADMIN_ROLE, config.ADMIN_USER_ID, adminPasswordHash, encryptionKey, config.ADMIN_ROLE
        ))
    except Exception as error:
        print(f'[ERROR] Unable to init the database: {error}')
        raise error
    finally:
        print('[INFO] Database initialized with schema')
        print(f'[INFO] Admin user ID: {config.ADMIN_USER_ID}')
        print(f'[INFO] Admin username: {config.ADMIN_USERNAME}')
        print(f'[INFO] Admin password: {config.ADMIN_PASSWORD}')

def getDatabase():
    if 'db' not in g:
        g.db = sqlite3.connect(
            config.DATABASE_FILE_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def executeQuery(query, values=tuple()):
    try:
        db = getDatabase()
        cursor = db.execute(query, values)
        db.commit()
        return cursor
    except Exception as error:
        print(f'[ERROR] Unable to execute SQL query: {error}')
        if 'db' in locals():
            db.rollback()        
        raise error

def fetchOne(query, values=tuple(), parseAsDict=False):
    try:
        cursor = executeQuery(query, values)
        if not parseAsDict:
            return cursor.fetchone()
        
        result = cursor.fetchone()
        if result is None:
            return None

        return dict(result)
    except Exception as error:
        print(f'[ERROR] Unable to fetch one row: {error}')
        raise error

def fetchAll(query, values=tuple()):
    try:
        cursor = executeQuery(query, values)
        return cursor.fetchall()
    except Exception as error:
        print(f'[ERROR] Unable to fetch one row: {error}')
        raise error

def isUsernameExists(username):
    try:
        user = fetchOne('SELECT id FROM users WHERE username = ?', (username,))
        return user is not None
    except Exception as error:
        print(f'[ERROR] Unable to check if username exists: {error}')
        raise error

def register(username, hashedPassword, encryptionKey, role=config.DEFAULT_USER_ROLE):
    try:
        if isUsernameExists(username):
            raise ValidationError('Username already exists')
        
        userId = str(uuid4())
        query = '''
        INSERT INTO users (id, username, password, encryption_key, role)
        VALUES (?, ?, ?, ?, ?)
        '''
        executeQuery(query, (userId, username, hashedPassword, encryptionKey, role))
        return userId
    except Exception as error:
        print(f'[ERROR] Unable to register user: {error}')
        raise error

def getUserByUsername(username):
    try:
        user = fetchOne('SELECT * FROM users WHERE username = ?', (username,), True)
        if user is None:
            raise ValidationError('User not found')
        return user
    except Exception as error:
        print(f'[ERROR] Unable to fetch user by username: {error}')
        raise error

def getUserIdByUsername(username):
    try:
        user = fetchOne('SELECT id FROM users WHERE username = ?', (username,))
        if user is None:
            raise ValidationError('User not found')
        
        return user['id']
    except Exception as error:
        print(f'[ERROR] Unable to fetch user ID by username: {error}')
        raise error

def getUserById(userId):
    try:
        user = fetchOne('SELECT * FROM users WHERE id = ?', (userId,), True)
        return user
    except Exception as error:
        print(f'[ERROR] Unable to fetch user by ID: {error}')
        raise error

def getUserEncryptionKey(userId, fileId=str()):
    try:
        if not fileId:
            user = fetchOne('SELECT encryption_key FROM users WHERE id = ?', (userId,))
        else:
            user = fetchOne('SELECT u.encryption_key FROM users u JOIN files f ON u.id = f.owner_id WHERE f.id = ?', (fileId,))
        if user is None:
            raise ValidationError('User not found')
        
        return user['encryption_key']
    except Exception as error:
        print(f'[ERROR] Unable to fetch user encryption key: {error}')
        raise error

def getUserUploadedOrSharedFilesId(userId):
    try:
        getUploadedOrSharedFilesQuery = '''
        SELECT f.id, f.original_filename, f.created_at, f.owner_id,
                CASE WHEN f.owner_id = ? THEN 1 ELSE 0 END as is_owner
        FROM files f
        LEFT JOIN shared_files sf ON f.id = sf.file_id
        WHERE f.owner_id = ? OR sf.shared_with_id = ?
        ORDER BY f.created_at DESC
        '''
        files = fetchAll(getUploadedOrSharedFilesQuery, (userId, userId, userId))
        return files
    except Exception as error:
        print(f'[ERROR] Unable to fetch user uploaded or shared files ID: {error}')
        raise error

def getUserSharedFiles(userId):
    try:
        getSharedFilesQuery = '''
        SELECT f.id, f.original_filename, f.created_at, f.owner_id, 
                u1.username as owner_username,
                CASE WHEN f.owner_id = ? THEN 1 ELSE 0 END as is_owner,
                sf.shared_with_id, u2.username as shared_with_username
        FROM files f
        LEFT JOIN shared_files sf ON f.id = sf.file_id
        LEFT JOIN users u1 ON f.owner_id = u1.id
        LEFT JOIN users u2 ON sf.shared_with_id = u2.id
        WHERE f.owner_id = ? OR sf.shared_with_id = ?
        ORDER BY f.created_at DESC
        '''
        files = fetchAll(getSharedFilesQuery, (userId, userId, userId))
        return files
    except Exception as error:
        print(f'[ERROR] Unable to fetch user shared files: {error}')
        raise error

def getUserUploadedFiles(userId):
    try:
        getUploadedFilesQuery = '''
        SELECT f.id, f.original_filename, f.created_at, f.owner_id, u.username as owner_username,
                CASE WHEN f.owner_id = ? THEN 1 ELSE 0 END as is_owner
        FROM files f
        LEFT JOIN users u ON f.owner_id = u.id
        WHERE f.owner_id = ?
        ORDER BY f.created_at DESC
        '''
        files = fetchAll(getUploadedFilesQuery, (userId, userId))
        return files
    except Exception as error:
        print(f'[ERROR] Unable to fetch user uploaded or shared files ID: {error}')
        raise error

def getUploadedFileRecord(fileId, userId):
    try:
        getFileRecordQuery = '''
        SELECT f.* FROM files f
            WHERE f.id = ? AND f.owner_id = ?
        '''
        fileRecord = fetchOne(getFileRecordQuery, (fileId, userId), True)
        if fileRecord is None:
            raise ValidationError('File not found or not owned by you')
        return fileRecord
    except Exception as error:
        print(f'[ERROR] Unable to fetch uploaded file record: {error}')
        raise error

def getUploadedOrSharedFileRecord(fileId, userId):
    try:
        getFileRecordQuery = '''
        SELECT f.* FROM files f
            WHERE f.id = ? AND (f.owner_id = ? OR EXISTS (
                SELECT 1 FROM shared_files sf WHERE sf.file_id = f.id AND sf.shared_with_id = ?
            ))
        '''
        fileRecord = fetchOne(getFileRecordQuery, (fileId, userId, userId), True)
        if fileRecord is None:
            raise ValidationError('File not found or not accessible')
        return fileRecord
    except Exception as error:
        print(f'[ERROR] Unable to fetch file record: {error}')
        raise error

def getAuditLogs():
    try:
        getAuditLogsQuery = '''
            SELECT al.*, u.username 
            FROM audit_logs al 
            JOIN users u ON al.user_id = u.id 
            ORDER BY al.created_at DESC
        '''
        logs = fetchAll(getAuditLogsQuery)
        return logs
    except Exception as error:
        print(f'[ERROR] Unable to fetch audit logs: {error}')
        raise error

def getMfaVerifyToken(userId):
    try:
        token = fetchOne('SELECT mfa_verify_token, mfa_verify_token_expiry FROM users WHERE id = ?', (userId,))
        if token is None:
            raise ValidationError('User not found')
        
        return {'token': token['mfa_verify_token'], 'expiryDate': token['mfa_verify_token_expiry']}
    except Exception as error:
        print(f'[ERROR] Unable to fetch MFA verify token: {error}')
        raise error

def getMfaUserEmail(userId):
    try:
        email = fetchOne('SELECT mfa_email FROM users WHERE id = ?', (userId,))
        if email is None:
            raise ValidationError('User not found')
        
        return email['mfa_email']
    except Exception as error:
        print(f'[ERROR] Unable to fetch MFA user email: {error}')
        raise error

def initMfa(userId):
    try:
        mfaCode = utils.authenticator.generateMfaCode()
        query = f'''
        UPDATE users SET mfa_code = ?, mfa_code_expiry = datetime('now', '+{config.MFA_CODE_EXPIRE_MINUTE} minute'), mfa_verify_token = NULL WHERE id = ?
        '''
        executeQuery(query, (mfaCode, userId))

        email = getMfaUserEmail(userId)
        utils.mail.send(email, 'MFA Code', f'Your MFA code is: {mfaCode}')
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to initialize MFA: {error}')
        raise error

def isMfaEnabled(userId):
    try:
        user = getUserById(userId)
        if user is None:
            raise ValidationError('User not found')
        
        return user['mfa_enabled'] == 1
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to fetch MFA status: {error}')
        raise error

def isMfaPending(userId):
    try:
        token = fetchOne('SELECT mfa_code FROM users WHERE mfa_code IS NOT NULL AND id = ?', (userId,))
        if token is None:
            return False
        return True
    except Exception as error:
        print(f'[ERROR] Unable to check if MFA is pending: {error}')
        raise error

def login(username, password):
    try:
        user = getUserByUsername(username)
        passwordHash = user['password']
        isCorrectPassword = utils.password.verifyBcryptHash(password, passwordHash)
        if not isCorrectPassword:
            raise ValidationError('Invalid username or password')
        
        return user
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to login user: {error}')
        raise error

def resetPassword(userId, newPassword):
    try:
        hashedNewPassword = utils.password.generateBcryptHash(newPassword)
        user = getUserById(userId)
        if user is None:
            raise ValidationError('User not found')

        executeQuery('UPDATE users SET password = ? WHERE id = ?', (hashedNewPassword, userId))
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to reset password: {error}')
        raise error

def insertFileRecord(fileId, ownerId, filename, originalFilename):
    try:
        query = '''
        INSERT INTO files (id, owner_id, filename, original_filename)
        VALUES (?, ?, ?, ?)
        '''
        executeQuery(query, (fileId, ownerId, filename, originalFilename))
    except Exception as error:
        print(f'[ERROR] Unable to insert file record: {error}')
        raise error

def checkFileAlreadySharedToUser(fileId, sharedWithId):
    try:
        query = '''
        SELECT * FROM shared_files
        WHERE file_id = ? AND shared_with_id = ?
        '''
        result = fetchOne(query, (fileId, sharedWithId))
        if result is not None:
            raise ValidationError('File already shared with this user')
    except Exception as error:
        print(f'[ERROR] Unable to check if file is already shared: {error}')
        raise error

def shareFile(fileId, ownerId, sharedWithUsername):
    try:
        file = getUploadedFileRecord(fileId, ownerId)
        shareUser = getUserByUsername(sharedWithUsername)
        checkFileAlreadySharedToUser(fileId, shareUser['id'])

        query = '''
        INSERT INTO shared_files (file_id, shared_with_id)
        VALUES (?, ?)
        '''
        executeQuery(query, (file['id'], shareUser['id']))
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to share file: {error}')
        raise error

def deleteFileRecord(fileId, userId):
    try:
        fileRecord = getUploadedFileRecord(fileId, userId)
        query = '''
        DELETE FROM files WHERE id = ? AND owner_id = ?
        '''
        executeQuery(query, (fileRecord['id'], userId))
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to delete file record: {error}')
        raise error

def unsetMfaVerifyToken(userId):
    try:
        query = '''
        UPDATE users SET mfa_verify_token = NULL, mfa_verify_token_expiry = NULL WHERE id = ?
        '''
        executeQuery(query, (userId,))
    except Exception as error:
        print(f'[ERROR] Unable to unset MFA verify token: {error}')
        raise error

def setMfaEnabledStatus(userId, status):
    try:
        query = '''
        UPDATE users SET mfa_enabled = ? WHERE id = ?
        '''
        executeQuery(query, (status, userId))
    except Exception as error:
        print(f'[ERROR] Unable to set MFA enabled status: {error}')
        raise error

def setupMfaFirstStep(userId, token, email):
    try:
        query = f'''
        UPDATE users SET mfa_verify_token = ?, mfa_verify_token_expiry = datetime('now', '+{config.MFA_CODE_EXPIRE_MINUTE} minute'), mfa_email = ? WHERE id = ?
        '''
        executeQuery(query, (token, email, userId))
    except Exception as error:
        print(f'[ERROR] Unable to setup MFA: {error}')
        raise error

def setupMfaSecondStep(userId, token):
    try:
        verifyToken = getMfaVerifyToken(userId)
        if verifyToken['token'] != token:
            raise ValidationError('Invalid MFA verify token')
        
        parsedDatetime = datetime.strptime(verifyToken['expiryDate'], config.SQLITE_DATETIME_FORMAT)
        if parsedDatetime > datetime.now():
            unsetMfaVerifyToken(userId)
            raise ValidationError('MFA verify token expired')
        
        unsetMfaVerifyToken(userId)
        setMfaEnabledStatus(userId, True)
        token = utils.authenticator.setMfaStatus(True)
        return token
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to setup MFA: {error}')
        raise error

def unsetMfaCode(userId):
    try:
        query = '''
        UPDATE users SET mfa_code = NULL, mfa_code_expiry = NULL WHERE id = ?
        '''
        executeQuery(query, (userId,))
    except Exception as error:
        print(f'[ERROR] Unable to unset MFA code: {error}')
        raise error

def verifyMfaCode(username, mfaCode):
    try:
        user = getUserByUsername(username)
        if user is None:
            raise ValidationError('User not found')
        if user['mfa_code'] != mfaCode:
            raise ValidationError('Invalid MFA code')
        
        parsedDatetime = datetime.strptime(user['mfa_code_expiry'], config.SQLITE_DATETIME_FORMAT)
        if parsedDatetime > datetime.now():
            unsetMfaCode(user['id'])
            raise ValidationError('MFA code expired')
        
        unsetMfaCode(user['id'])
        return user
    except ValidationError as error:
        raise error
    except Exception as error:
        print(f'[ERROR] Unable to verify MFA code: {error}')
        raise error

def closeDatabase(error=None):
    if error:
        print(f'[ERROR] Unable to close the database connection: {error}')
        return

    db = g.pop('db', None)
    if db is not None:
        db.close()

def initDatabase(app):
    app.teardown_appcontext(closeDatabase)
    with app.app_context():
        initDatabaseWithSchema()