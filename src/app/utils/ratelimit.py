from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = None

def getLimiter(app=None):
    global limiter
    if limiter:
        return limiter
    
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=['50 per hour']
    )
    return limiter