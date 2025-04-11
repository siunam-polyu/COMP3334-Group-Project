from flask import Flask, request
from views import viewsRoute
from api import apiRoute
from utils.database import initDatabase
from utils.authenticator import isAuthenticated, verifyJwt
from utils.ratelimit import limiter
from os import urandom
import config

app = Flask(__name__)
limiter.init_app(app)

app.register_blueprint(viewsRoute)
app.register_blueprint(apiRoute, url_prefix='/api')

app.config['SECRET_KEY'] = urandom(128)
app.config['JWT_SECRET_KEY'] = urandom(128)
app.config['MAX_CONTENT_LENGTH'] = config.MAXIMUM_100MB_FILESIZE

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
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('../cert.pem', '../key.pem')

    app.run('0.0.0.0', port=config.APP_PORT, ssl_context=context, debug=True)