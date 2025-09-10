# qr.py  — multi-use QR tokens (no burn), 5-minute expiry, CORS enabled
import os
import time
import uuid
import jwt
from flask import Blueprint, jsonify, request
from flask_cors import CORS

qr_bp = Blueprint("qr", __name__)

# Config
JWT_SECRET = os.getenv("QR_JWT_SECRET", "change-me")         # ⚠️ set a real secret in env
JWT_ISSUER = "attendance-app"
LIFETIME = int(os.getenv("QR_TOKEN_LIFETIME_SECONDS", "300")) # 5 minutes
LEEWAY = 1                                                    # small clock skew

@qr_bp.get("/qr/token")
def qr_token():
    """Issue a short-lived JWT encoded into the QR. Multi-use during lifetime."""
    now = int(time.time())
    payload = {
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + LIFETIME,
        "jti": str(uuid.uuid4()),           # unique per token (for auditing), not burned
        "scope": "attendance:checkin",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token, "expires_in": LIFETIME})

@qr_bp.post("/qr/verify")
def qr_verify():
    """Verify signature/issuer/expiry. Do NOT burn token: many students can use it."""
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token:
        return jsonify(success=False, message="Missing token"), 400

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            leeway=LEEWAY,
            options={"require": ["exp", "iss", "iat"]},
        )
        # If you ever want single-use behavior, add a server-side JTI store here.
        return jsonify(success=True, exp=payload["exp"], iat=payload["iat"], scope=payload.get("scope"))
    except jwt.ExpiredSignatureError:
        return jsonify(success=False, message="QR expired"), 401
    except jwt.InvalidIssuerError:
        return jsonify(success=False, message="Invalid issuer"), 401
    except Exception:
        return jsonify(success=False, message="Invalid token"), 401

# --- Dev server ---
if __name__ == "__main__":
    from flask import Flask

    app = Flask(__name__)

    # Allow React dev server to call this API
    CORS(
        app,
        resources={
            r"/qr/*": {
                "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
                "methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type"],
                "supports_credentials": False,
            }
        },
    )

    app.register_blueprint(qr_bp)

    # IMPORTANT before running:
    # export QR_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    # (optional) export QR_TOKEN_LIFETIME_SECONDS=300
    app.run(host="127.0.0.1", port=5001, debug=True)
