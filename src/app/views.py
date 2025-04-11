from flask import Blueprint, render_template, make_response, redirect, url_for, request
import utils.authenticator
import utils.authorizor
import utils.database
import config
import utils.validator

viewsRoute = Blueprint('views', __name__, template_folder='templates')

@viewsRoute.route('/', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def index():
    return render_template('index.html', title='Home')

@viewsRoute.route('/files', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def viewUploadedFiles():
    try:
        files = utils.database.getUserUploadedFiles(request.user['id'])
        return render_template('files.html', title='Uploaded Files', files=files)
    except Exception as error:
        print('[ERROR] Error while fetching files:', error)
        return render_template('500.html', title='Error'), 500

@viewsRoute.route('/shared', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def viewSharedFiles():
    try:
        files = utils.database.getUserSharedFiles(request.user['id'])
        return render_template('shared_files.html', title='Shared Files', files=files)
    except Exception as error:
        print('[ERROR] Error while fetching files:', error)
        return render_template('500.html', title='Error'), 500

@viewsRoute.route('/profile', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def profile():
    return render_template('profile.html', title='User Profile')

@viewsRoute.route('/audit-logs', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
@utils.authorizor.roleRequired(config.ADMIN_ROLE, isView=True)
def viewAuditLogs():
    try:
        logs = utils.database.getAuditLogs()
        return render_template('audit_logs.html', title='Audit Logs', logs=logs)
    except Exception as error:
        print('[ERROR] Error while fetching audit logs:', error)
        return render_template('500.html', title='Error'), 500

@viewsRoute.route('/login', methods=('GET',))
@utils.authenticator.isNotAuthenticatedWrapper(isView=True)
def login():
    return render_template('login.html', title='Login')

@viewsRoute.route('/mfa', methods=('GET',))
@utils.authenticator.isNotAuthenticatedWrapper(isView=True)
def mfa():
    try:
        username = request.args.get('username')
        utils.validator.validateMfaRequest(username)

        return render_template('mfa.html', title='MFA Required')
    except utils.validator.ValidationError as error:
        return render_template('500.html', title='Error', error=error.message), 500
    except Exception as error:
        print('[ERROR] Error while checking MFA status:', error)
        return render_template('500.html', title='Error'), 500

@viewsRoute.route('/register', methods=('GET',))
@utils.authenticator.isNotAuthenticatedWrapper(isView=True)
def register():
    return render_template('register.html', title='Register')

@viewsRoute.route('/logout', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def logout():
    response = make_response(redirect(url_for('views.login')))
    response.set_cookie('session', '', httponly=True, samesite='Strict')
    return response