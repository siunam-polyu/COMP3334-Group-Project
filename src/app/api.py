from flask import Blueprint, request, jsonify, make_response
from utils.ratelimit import getLimiter
from utils.logger import logUserAction
import utils.validator
import utils.database
import utils.password
import utils.encryptor
import utils.authenticator
import utils.file
# import base64
# import pyotp
# import qrcode

apiRoute = Blueprint('api', __name__)
limiter = getLimiter()

@apiRoute.route('/register', methods=['POST'])
@limiter.limit('5 per minute')
@utils.authenticator.isNotAuthenticatedWrapper()
def register():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        utils.validator.validateRegisterForm(username, password)

        encryptionKey = utils.encryptor.generateEncryptionKey()
        hashedPassword = utils.password.generateBcryptHash(password)
        utils.database.register(username, hashedPassword, encryptionKey)
        
        return jsonify({'status': True, 'message': 'User registered successfully'}), 200
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] Registration error: {error}')
        return jsonify({'status': False, 'message': 'Registration failed'}), 500

@apiRoute.route('/login', methods=('POST',))
@limiter.limit('5 per minute')
@utils.authenticator.isNotAuthenticatedWrapper()
def login():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        utils.validator.validateLoginForm(username, password)

        user = utils.database.login(username, password)
        logUserAction(user['id'], 'login')

        payload = {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
        }
        if user['mfa_secret']:
            payload['mfa_pending'] = True
            token = utils.authenticator.getMfaToken(payload)
            response = make_response(
                jsonify({
                    'status': True,
                    'message': 'MFA required',
                    'temp_token': token
                })
                , 200
            )
            response.set_cookie('session', token, httponly=True, samesite='Strict')
            return response
        
        token = utils.authenticator.signJwt(payload)
        response = make_response(
            jsonify({
                'status': True, 'message': 'Logged in successfully', 'token': token
            }),
            200
        )
        response.set_cookie('session', token, httponly=True, samesite='Strict')
        return response
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'Login error: {error}')
        return jsonify({'status': False, 'message': 'Unable to login'}), 500

@apiRoute.route('/reset-password', methods=('POST',))
@limiter.limit('5 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def resetPassword():
    try:
        currentPassword = request.form.get('current-password')
        newPassword = request.form.get('new-password')
        confirmNewPassword = request.form.get('confirm-new-password')
        utils.validator.validateNewPassword(currentPassword, newPassword, confirmNewPassword)
        
        utils.database.resetPassword(request.user['id'], newPassword)
        logUserAction(request.user['id'], 'reset password')

        response = make_response(
            jsonify({'status': True, 'message': 'Password reset successfully'}),
            200
        )
        response.set_cookie('session', '', httponly=True, samesite='Strict')
        return response
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'Password reset error: {error}')
        return jsonify({'status': False, 'message': 'Password reset failed'}), 500

@apiRoute.route('/upload', methods=('POST',))
@limiter.limit('10 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def upload():
    try:
        utils.validator.validateFileUploadForm(request.files)

        uploadedFileId = utils.file.upload(request.user['id'], request.files['file'])
        logUserAction(request.user['id'], f'Uploaded file. File ID: {uploadedFileId}')
        
        return jsonify({
            'status': True,
            'message': 'File uploaded successfully',
            'fileId': uploadedFileId
        }), 200
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'File upload error: {error}')
        return jsonify({'status': False, 'message': 'File upload failed'}), 500

# # Add new routes for MFA
# # @app.route('/setup-mfa', methods=['POST'])
# # def setup_mfa():
# #     token = request.headers.get('Authorization')
# #     if not token:
# #         return jsonify({'error': 'Missing token'}), 401
    
# #     try:
# #         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
# #         user_id = payload['user_id']
# #     except:
# #         return jsonify({'error': 'Invalid token'}), 401
    
# #     conn = get_db()
# #     try:
# #         # Generate a new secret key
# #         secret = pyotp.random_base32()
        
# #         # Generate QR code
# #         totp = pyotp.TOTP(secret)
# #         provisioning_uri = totp.provisioning_uri(
# #             name=f"user_{user_id}",
# #             issuer_name="Secure File Storage"
# #         )
        
# #         # Convert QR code to base64
# #         qr = qrcode.QRCode(version=1, box_size=10, border=5)
# #         qr.add_data(provisioning_uri)
# #         qr.make(fit=True)
# #         img = qr.make_image(fill_color="black", back_color="white")
        
# #         # Convert image to base64
# #         buffered = io.BytesIO()
# #         img.save(buffered, format="PNG")
# #         qr_code = base64.b64encode(buffered.getvalue()).decode()
        
# #         # Store the secret in the database
# #         conn.execute('UPDATE users SET mfa_secret = ? WHERE id = ?', (secret, user_id))
# #         conn.commit()
        
# #         logUserAction(user_id, 'setup mfa')
# #         return jsonify({
# #             'message': 'MFA setup successful',
# #             'secret': secret,
# #             'qr_code': qr_code
# #         }), 200
# #     except Exception as e:
# #         print(f"MFA setup error: {e}")
# #         return jsonify({'error': 'MFA setup failed'}), 500
# #     finally:
# #         if 'conn' in locals():
# #             conn.close()

# @app.route('/verify-mfa', methods=['POST'])
# def verify_mfa():
#     data = request.json
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Missing token'}), 401
    
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401
    
#     mfa_code = data.get('mfa_code')
#     if not mfa_code:
#         return jsonify({'error': 'MFA code is required'}), 400
    
#     conn = get_db()
#     user = conn.execute('SELECT mfa_secret FROM users WHERE id = ?', (user_id,)).fetchone()
#     conn.close()
    
#     if not user or not user['mfa_secret']:
#         return jsonify({'error': 'MFA not set up'}), 400
    
#     totp = pyotp.TOTP(user['mfa_secret'])
#     if not totp.verify(mfa_code):
#         return jsonify({'error': 'Invalid MFA code'}), 401
    
#     return jsonify({'message': 'MFA verified successfully'}), 200

# @app.route('/files', methods=['GET'])
# def list_files():
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Missing token'}), 401
    
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401
    
#     conn = get_db()
#     try:
#         # Get files owned by user or shared with user
#         files = conn.execute('''
#             SELECT f.id, f.filename, f.created_at, f.owner_id,
#                    CASE WHEN f.owner_id = ? THEN 1 ELSE 0 END as is_owner
#             FROM files f
#             LEFT JOIN shared_files sf ON f.id = sf.file_id
#             WHERE f.owner_id = ? OR sf.shared_with_id = ?
#             ORDER BY f.created_at DESC
#         ''', (user_id, user_id, user_id)).fetchall()
        
#         return jsonify([dict(file) for file in files]), 200
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
#     finally:
#         conn.close()

# @app.route('/download/<int:file_id>', methods=['GET'])
# def download(file_id):
#     try:
#         token = request.headers.get('Authorization')
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401

#     conn = get_db()
#     file = conn.execute('''
#         SELECT f.*, u.encryption_key
#         FROM files f
#         JOIN users u ON f.owner_id = u.id
#         WHERE f.id = ? AND (f.owner_id = ? OR EXISTS (
#             SELECT 1 FROM shared_files sf WHERE sf.file_id = f.id AND sf.shared_with_id = ?
#         ))
#     ''', (file_id, user_id, user_id)).fetchone()

#     if not file:
#         return jsonify({'error': 'File not found or access denied'}), 404

#     try:
#         # Decrypt file content
#         fernet = Fernet(file['encryption_key'])
#         decrypted_content = fernet.decrypt(file['encrypted_data'])
        
#         # Create response with file
#         response = make_response(decrypted_content)
#         response.headers['Content-Disposition'] = f'attachment; filename="{file["filename"]}"'
#         response.headers['Content-Type'] = 'application/octet-stream'
#         return response
#     except Exception as e:
#         print(f"Error decrypting file: {e}")
#         return jsonify({'error': 'Error processing file'}), 500

# @app.route('/share', methods=['POST'])
# def share_file():
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Missing token'}), 401
    
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401
    
#     data = request.json
#     file_id = data.get('file_id')
#     share_with_username = data.get('username')
    
#     conn = get_db()
#     # Verify file ownership
#     file = conn.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?', 
#                        (file_id, user_id)).fetchone()
#     if not file:
#         return jsonify({'error': 'File not found or not owned by you'}), 404
    
#     # Get user to share with
#     share_user = conn.execute('SELECT id FROM users WHERE username = ?', 
#                             (share_with_username,)).fetchone()
#     if not share_user:
#         return jsonify({'error': 'User not found'}), 404
    
#     try:
#         conn.execute('INSERT INTO shared_files (file_id, shared_with_user_id) VALUES (?, ?)',
#                     (file_id, share_user['id']))
#         conn.commit()
#         logUserAction(user_id, f'shared file {file_id} with user {share_with_username}')
#         return jsonify({'message': 'File shared successfully'}), 200
#     except sqlite3.IntegrityError:
#         return jsonify({'error': 'File already shared with this user'}), 400
#     finally:
#         conn.close()

# @app.route('/audit-logs', methods=['GET'])
# def get_audit_logs():
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Missing token'}), 401
    
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401
    
#     # For simplicity, we'll assume user_id 1 is the admin
#     if user_id != 1:
#         return jsonify({'error': 'Unauthorized'}), 403
    
#     conn = get_db()
#     logs = conn.execute('''
#         SELECT al.*, u.username 
#         FROM audit_logs al 
#         JOIN users u ON al.user_id = u.id 
#         ORDER BY al.timestamp DESC
#     ''').fetchall()
    
#     return jsonify([dict(log) for log in logs]), 200

# # Add efficient file update route
# @app.route('/update-chunk', methods=['POST'])
# def update_chunk():
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Missing token'}), 401
    
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401
    
#     data = request.json
#     filepath = data.get('filepath')
#     start_offset = data.get('start_offset')
#     chunk_data = base64.b64decode(data.get('chunk_data'))
    
#     if not all([filepath, start_offset is not None, chunk_data]):
#         return jsonify({'error': 'Missing required parameters'}), 400
    
#     conn = get_db()
#     try:
#         # Get file and verify ownership
#         file = conn.execute('''
#             SELECT f.*, u.encryption_key 
#             FROM files f 
#             JOIN users u ON f.owner_id = u.id 
#             WHERE f.filename = ? AND f.owner_id = ?
#         ''', (filepath, user_id)).fetchone()
        
#         if not file:
#             return jsonify({'error': 'File not found or not owned by you'}), 404
        
#         # Decrypt existing file data
#         f = Fernet(file['encryption_key'])
#         decrypted_data = f.decrypt(file['encrypted_data'])
        
#         # Update the chunk
#         updated_data = bytearray(decrypted_data)
#         updated_data[start_offset:start_offset + len(chunk_data)] = chunk_data
        
#         # Re-encrypt the updated data
#         encrypted_data = f.encrypt(bytes(updated_data))
        
#         # Update the file in database
#         conn.execute('''
#             UPDATE files 
#             SET encrypted_data = ? 
#             WHERE id = ?
#         ''', (encrypted_data, file['id']))
        
#         conn.commit()
#         logUserAction(user_id, f'updated chunk in file: {filepath}')
#         return jsonify({'message': 'File chunk updated successfully'}), 200
        
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
#     finally:
#         conn.close()

# # Add file versioning support
# def create_file_version(conn, file_id, encrypted_data):
#     """Create a new version of a file."""
#     conn.execute('''
#         INSERT INTO file_versions (file_id, encrypted_data, created_at)
#         VALUES (?, ?, CURRENT_TIMESTAMP)
#     ''', (file_id, encrypted_data))
#     conn.commit()

# # Add file version retrieval
# @app.route('/file-versions/<int:file_id>', methods=['GET'])
# def get_file_versions(file_id):
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Missing token'}), 401
    
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401
    
#     conn = get_db()
#     try:
#         # Verify file ownership
#         file = conn.execute('''
#             SELECT * FROM files 
#             WHERE id = ? AND owner_id = ?
#         ''', (file_id, user_id)).fetchone()
        
#         if not file:
#             return jsonify({'error': 'File not found or not owned by you'}), 404
        
#         # Get file versions
#         versions = conn.execute('''
#             SELECT id, created_at 
#             FROM file_versions 
#             WHERE file_id = ? 
#             ORDER BY created_at DESC
#         ''', (file_id,)).fetchall()
        
#         return jsonify([dict(v) for v in versions]), 200
        
#     finally:
#         conn.close()

# # Add file version restore
# @app.route('/restore-version/<int:file_id>/<int:version_id>', methods=['POST'])
# def restore_file_version(file_id, version_id):
#     token = request.headers.get('Authorization')
#     if not token:
#         return jsonify({'error': 'Missing token'}), 401
    
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload['user_id']
#     except:
#         return jsonify({'error': 'Invalid token'}), 401
    
#     conn = get_db()
#     try:
#         # Verify file ownership
#         file = conn.execute('''
#             SELECT * FROM files 
#             WHERE id = ? AND owner_id = ?
#         ''', (file_id, user_id)).fetchone()
        
#         if not file:
#             return jsonify({'error': 'File not found or not owned by you'}), 404
        
#         # Get version data
#         version = conn.execute('''
#             SELECT encrypted_data 
#             FROM file_versions 
#             WHERE id = ? AND file_id = ?
#         ''', (version_id, file_id)).fetchone()
        
#         if not version:
#             return jsonify({'error': 'Version not found'}), 404
        
#         # Update current file with version data
#         conn.execute('''
#             UPDATE files 
#             SET encrypted_data = ? 
#             WHERE id = ?
#         ''', (version['encrypted_data'], file_id))
        
#         conn.commit()
#         logUserAction(user_id, f'restored version {version_id} of file {file_id}')
#         return jsonify({'message': 'File version restored successfully'}), 200
        
#     finally:
#         conn.close()