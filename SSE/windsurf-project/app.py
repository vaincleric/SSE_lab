import os
import time
import jwt
from functools import wraps
from flask import Flask, jsonify, request, abort

app = Flask(__name__)

JWT_SECRET = os.environ.get("APP_JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("APP_JWT_SECRET environment variable not set")

def generate_token(sub: str, scopes: list, expires_in_seconds: int = 3600):
    now = int(time.time())
    payload = {
        "sub": sub,
        "scopes": scopes,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode()
    return token

def require_scope(required_scope):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                abort(401)
            token = auth.split(" ", 1)[1].strip()
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                abort(401)
            except jwt.InvalidTokenError:
                abort(401)

            scopes = payload.get("scopes", [])
            if not isinstance(scopes, list) or required_scope not in scopes:
                abort(403)
            request.user = payload.get("sub")
            request.token_payload = payload
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.get("/")
def index():
    return jsonify({"status": "ok", "message": "Hello from Flask in Docker!"})

@app.get("/secure")
@require_scope("encrypt")
def secure():
    return jsonify({"status": "ok", "user": getattr(request, "user", None)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
