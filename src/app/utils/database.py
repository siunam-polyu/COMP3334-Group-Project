import sqlite3
import utils.password
import utils.encryptor
from flask import g
from utils.validator import ValidationError
from uuid import uuid4

DATABASE_FILE_PATH = 'database.db'
ADMIN_ROLE = 'Admin'
DEFAULT_USER_ROLE = 'Guest'
ADMIN_USERNAME = 'admin'
ADMIN_USER_ID = str(uuid4())
ADMIN_PASSWORD = utils.password.generatePassword(60)

def initDatabaseWithSchema():
    adminPasswordHash = utils.password.generateBcryptHash(ADMIN_PASSWORD).decode()
    encryptionKey = utils.encryptor.generateEncryptionKey().decode()

    schema = f'''
    -- Users table with MFA support
    CREATE TABLE IF NOT EXISTS users (
        id TEXT CHECK(length(id) = 36) PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        encryption_key TEXT NOT NULL,
        role TEXT DEFAULT '{DEFAULT_USER_ROLE}',
        mfa_secret TEXT,
        mfa_enabled BOOLEAN DEFAULT 0,
        last_login DATETIME,
        failed_login_attempts INTEGER DEFAULT 0,
        account_locked BOOLEAN DEFAULT 0,
        account_locked_until DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Files table
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users (id)
    );

    -- File versions table for versioning support
    CREATE TABLE IF NOT EXISTS file_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files (id)
    );

    -- Shared files table
    CREATE TABLE IF NOT EXISTS shared_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        shared_with_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files (id),
        FOREIGN KEY (shared_with_id) REFERENCES users (id)
    );

    -- Audit logs table
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- Create admin user if not exists
    INSERT INTO users (id, username, password, encryption_key, role)
        VALUES ('{ADMIN_USER_ID}', '{ADMIN_USERNAME}', '{adminPasswordHash}', '{encryptionKey}', '{ADMIN_ROLE}')
        ON CONFLICT(username) DO UPDATE SET id = '{ADMIN_USER_ID}', password = '{adminPasswordHash}', encryption_key = '{encryptionKey}', role = '{ADMIN_ROLE}';
    '''
    
    db = getDatabase()
    try:
        db.executescript(schema)
        db.commit()
    except Exception as error:
        print(f'[ERROR] Unable to init the database: {error}')
        raise error
    finally:
        print('[INFO] Database initialized with schema')
        print(f'[INFO] Admin user ID: {ADMIN_USER_ID}')
        print(f'[INFO] Admin username: {ADMIN_USERNAME}')
        print(f'[INFO] Admin password: {ADMIN_PASSWORD}')
        print(f'[INFO] Admin encryption key: {encryptionKey}')
        db.close()

def getDatabase():
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE_FILE_PATH,
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
        
        return dict(cursor.fetchone())
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

def register(username, hashedPassword, encryptionKey, role=DEFAULT_USER_ROLE):
    try:
        if isUsernameExists(username):
            raise ValidationError('Username already exists')
        
        userId = str(uuid4())
        query = '''
        INSERT INTO users (id, username, password, encryption_key, role)
        VALUES (?, ?, ?, ?, ?)
        '''
        executeQuery(query, (userId, username, hashedPassword, encryptionKey, role))
    except Exception as error:
        print(f'[ERROR] Unable to register user: {error}')
        raise error

def getUserByUsername(username):
    try:
        user = fetchOne('SELECT * FROM users WHERE username = ?', (username,), True)
        return user
    except Exception as error:
        print(f'[ERROR] Unable to fetch user by username: {error}')
        raise error

def getUserIdByUsername(username):
    try:
        user = fetchOne('SELECT id FROM users WHERE username = ?', (username,))
        return user['id'] if user else None
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

def login(username, password):
    try:
        user = getUserByUsername(username)
        if user is None:
            raise ValidationError('Invalid username or password')

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