from flask import Blueprint, render_template, make_response, redirect, url_for
import utils.authenticator

viewsRoute = Blueprint('views', __name__, template_folder='templates')

@viewsRoute.route('/', methods=('GET',))
@utils.authenticator.isAuthenticatedWrapper(isView=True)
def index():
    return render_template('index.html', title='Home')

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