from flask import Blueprint, request, jsonify, make_response, redirect, url_for
from os import urandom
from utils.ratelimit import limiter
from utils.logger import logUserAction
import utils.validator
import utils.database
import utils.password
import utils.encryptor
import utils.authenticator
import utils.file
import utils.mail

apiRoute = Blueprint('api', __name__)

@apiRoute.route('/register', methods=('POST',))
@limiter.limit('5 per minute')
@utils.authenticator.isNotAuthenticatedWrapper()
def register():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        utils.validator.validateRegisterForm(username, password)

        encryptionKey = utils.encryptor.generateEncryptionKey()
        hashedPassword = utils.password.generateBcryptHash(password)
        userId = utils.database.register(username, hashedPassword, encryptionKey)
        logUserAction(userId, 'Registration', details=f'User ID {userId} has been registered')

        return jsonify({'status': True, 'message': 'User registered successfully'}), 200
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] Registration error: {error}')
        return jsonify({'status': False, 'message': 'Registration failed'}), 500

@apiRoute.route('/login', methods=('POST',))
@limiter.limit('3 per minute')
@utils.authenticator.isNotAuthenticatedWrapper()
def login():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        utils.validator.validateLoginForm(username, password)

        user = utils.database.login(username, password)
        if user['mfa_enabled']:
            utils.database.initMfa(user['id'])
            logUserAction(user['id'], 'MFA', details='Sent MFA code to the user email address')
            return jsonify({
                'status': True,
                'message': 'Your account has enabled MFA. Please check your email for the verification code',
                'mfa_enabled': True,
                'username': user['username']
            }), 200

        response = utils.authenticator.setLoggedInResponse(user)
        logUserAction(user['id'], 'Authentication', details='User logged in without MFA')
        return response
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] Login error: {error}')
        return jsonify({'status': False, 'message': 'Unable to login'}), 500

@apiRoute.route('/mfa/verify', methods=('POST',))
@limiter.limit('3 per minute')
@utils.authenticator.isNotAuthenticatedWrapper()
def verifyMfa():
    try:
        mfaCode = request.form.get('code')
        username = request.form.get('username')
        utils.validator.validateMfaVerifyForm(username, mfaCode)
        
        user = utils.database.verifyMfaCode(username, mfaCode)
        response = utils.authenticator.setLoggedInResponse(user, True)
        logUserAction(user['id'], 'MFA', details='MFA code verified and logged in')
        return response
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] MFA verification error: {error}')
        return jsonify({'status': False, 'message': 'MFA verification failed'}), 500

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
        logUserAction(request.user['id'], 'Authentication', 'Password reset successfully')

        response = make_response(
            jsonify({'status': True, 'message': 'Password reset successfully'}),
            200
        )
        response.set_cookie('session', '', httponly=True, samesite='Strict')
        return response
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] Password reset error: {error}')
        return jsonify({'status': False, 'message': 'Password reset failed'}), 500

@apiRoute.route('/setup-mfa-1', methods=('POST',))
@limiter.limit('1 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def setupMfaFirstStep():
    try:
        email = request.form.get('email')
        utils.validator.validateMfaSetupFirstStepForm(email)

        token = urandom(32).hex()
        utils.database.setupMfaFirstStep(request.user['id'], token, email)

        verifyLink = utils.authenticator.getMfaVerifyLink(token)
        utils.mail.send(
            email,
            'MFA Setup',
            f'Your MFA token is: {token}. Go to {verifyLink} to set up your MFA.'
        )
        logUserAction(request.user['id'], 'MFA', details='Completed the first step of MFA setup')

        return jsonify({'status': True, 'message': 'The first step of MFA setup succeed. Please complete the rest of the MFA setup steps by clicking the link in the email that just sent to you.' }), 200
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] MFA setup first step error: {error}')
        return jsonify({'status': False, 'message': 'MFA setup first step failed'}), 500

@apiRoute.route('/setup-mfa-2', methods=('GET',))
@limiter.limit('3 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def setupMfaSecondStep():
    try:
        token = request.args.get('token')
        utils.validator.validateMfaSetupSecondStepForm(token)

        token = utils.database.setupMfaSecondStep(request.user['id'], token)
        logUserAction(request.user['id'], 'MFA', details='Completed the second (Final) step of MFA setup')

        response = make_response(redirect(url_for('views.profile')))
        response.set_cookie('session', token, httponly=True, samesite='Strict')
        return response
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'MFA setup second step error: {error}')
        return jsonify({'status': False, 'message': 'MFA setup second step failed'}), 500

@apiRoute.route('/file/upload', methods=('POST',))
@limiter.limit('10 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def upload():
    try:
        utils.validator.validateFileUploadForm(request.files)

        uploadedFileId = utils.file.upload(request.user['id'], request.files['file'])
        logUserAction(request.user['id'], 'File', details=f'File with ID {uploadedFileId} is uploaded')
        
        return jsonify({
            'status': True,
            'message': 'File uploaded successfully',
            'fileId': uploadedFileId
        }), 200
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] File upload error: {error}')
        return jsonify({'status': False, 'message': 'File upload failed'}), 500

@apiRoute.route('/file/<fileId>/share/', methods=('POST',))
@limiter.limit('10 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def shareFile(fileId):
    try:
        shareWithUsername = request.form.get('share-with-username')
        utils.validator.validateShareFileForm(fileId, shareWithUsername)

        utils.database.shareFile(fileId, request.user['id'], shareWithUsername)
        logUserAction(request.user['id'], 'File', details=f'File with ID {fileId} is shared with user {shareWithUsername}')

        return jsonify({'status': True, 'message': 'File shared successfully'}), 200
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] File share error: {error}')
        return jsonify({'status': False, 'message': 'File share failed'}), 500

@apiRoute.route('/file/<fileId>', methods=('GET',))
@limiter.limit('10 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def download(fileId):
    try:
        utils.validator.validateFileDownloadForm(fileId)

        decryptedFile = utils.file.read(request.user['id'], fileId)
        logUserAction(request.user['id'], 'File', details=f'File with ID {fileId} is downloaded')

        response = make_response(decryptedFile['data'])
        response.headers['Content-Disposition'] = f'attachment; filename="{decryptedFile["filename"]}"'
        response.headers['Content-Type'] = 'application/octet-stream'
        return response
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] Error decrypting file: {error}')
        return jsonify({'status': False, 'messsage': 'Error processing file'}), 500

@apiRoute.route('/file/<fileId>', methods=('DELETE',))
@limiter.limit('10 per minute')
@utils.authenticator.isAuthenticatedWrapper()
def delete(fileId):
    try:
        utils.validator.validateFileDownloadForm(fileId)

        utils.file.delete(request.user['id'], fileId)
        logUserAction(request.user['id'], 'File', details=f'File with ID: {fileId} is deleted')

        return jsonify({'status': True, 'message': 'File deleted successfully'}), 200
    except utils.validator.ValidationError as error:
        return jsonify({'status': False, 'message': error.message}), 400
    except Exception as error:
        print(f'[ERROR] Error decrypting file: {error}')
        return jsonify({'status': False, 'messsage': 'Error processing file'}), 500