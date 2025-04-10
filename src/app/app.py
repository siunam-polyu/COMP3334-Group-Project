from flask import Flask, request
from views import viewsRoute
from api import apiRoute
from utils.database import initDatabase
from utils.ratelimit import getLimiter
from utils.authenticator import isAuthenticated, verifyJwt
from os import urandom

MAXIMUM_100MB_FILESIZE = 100 * 1024 * 1024

app = Flask(__name__)
app.register_blueprint(viewsRoute)
app.register_blueprint(apiRoute, url_prefix='/api')

app.config['SECRET_KEY'] = urandom(128)
app.config['JWT_SECRET_KEY'] = urandom(128)
app.config['MAX_CONTENT_LENGTH'] = MAXIMUM_100MB_FILESIZE

getLimiter(app)

with app.app_context():
    initDatabase(app)

@app.before_request
def authenticationMiddleware():
    request.isAuthenticated = isAuthenticated()
    if request.isAuthenticated:
        payload = verifyJwt(request.cookies.get('session'))
        request.user = payload
    else:
        request.user = None

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)