from flask import Blueprint, render_template, make_response, redirect, url_for, request
import utils.authenticator
import utils.database

viewsRoute = Blueprint('views', __name__, template_folder='templates')

@viewsRoute.route('/', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def index():
    return render_template('index.html', title='Home')

@viewsRoute.route('/files', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def viewUploadedFiles():
    try:
        files = utils.database.getUserUploadedOrSharedFilesId(request.user['id'])
        return render_template('files.html', title='Uploaded Files', files=files)
    except Exception as error:
        print('[ERROR] Error while fetching files:', error)
        return render_template('500.html', title='Error'), 500

@viewsRoute.route('/profile', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def profile():
    return render_template('profile.html', title='User Profile')

@viewsRoute.route('/login', methods=('GET',))
@utils.authenticator.isNotAuthenticatedWrapper(isView=True)
def login():
    return render_template('login.html', title='Login')

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