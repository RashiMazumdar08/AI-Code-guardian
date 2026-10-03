from functools import wraps

class UserSession:
    def __init__(self, user_id: str = "usr_100"):
        self.user_id = user_id
        self.is_active = True

active_session = UserSession(user_id="usr_100")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not active_session.is_active:
            raise Exception("Unauthorized")
        return f(*args, **kwargs)
    return decorated
