# app.py — multi-use QR tokens (no burn), 5-minute expiry, CORS enabled
import os
import time
import uuid
import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS

# Config
JWT_SECRET = os.getenv("QR_JWT_SECRET", "change-me")          # ⚠️ set a real secret in env
JWT_ISSUER = "attendance-app"
LIFETIME = int(os.getenv("QR_TOKEN_LIFETIME_SECONDS", "300")) # 5 minutes
LEEWAY = 1                                                     # small clock skew

app = Flask(__name__)   # 👈 Gunicorn will look for this
CORS(
    app,
    resources={
        r"/qr/*": {
            "origins": [
                os.getenv("FRONTEND_ORIGIN", "https://attendencefrontend.vercel.app/"),
                "http://127.0.0.1:3000",
            ],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
            "supports_credentials": False,
        }
    },
)

# -------------------
# Routes
# -------------------

@app.get("/qr/token")
def qr_token():
    """Issue a short-lived JWT encoded into the QR. Multi-use during lifetime."""
    now = int(time.time())
    payload = {
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + LIFETIME,
        "jti": str(uuid.uuid4()),           # unique per token (auditing), not burned
        "scope": "attendance:checkin",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token, "expires_in": LIFETIME})


@app.post("/qr/verify")
def qr_verify():
    """Verify signature/issuer/expiry. Multi-use, not burned after first use."""
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
        return jsonify(success=True, exp=payload["exp"], iat=payload["iat"], scope=payload.get("scope"))
    except jwt.ExpiredSignatureError:
        return jsonify(success=False, message="QR expired"), 401
    except jwt.InvalidIssuerError:
        return jsonify(success=False, message="Invalid issuer"), 401
    except Exception:
        return jsonify(success=False, message="Invalid token"), 401


# Health check (for Render)
@app.get("/healthz")
def healthz():
    return "ok", 200


# --- Dev server ---
if __name__ == "__main__":
    # IMPORTANT before running:
    # export QR_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    # (optional) export QR_TOKEN_LIFETIME_SECONDS=300
    app.run(host="0.0.0.0", port=5001, debug=True)
