# app.py (top)
import os, re
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# Allow production + dev (comma-separated env), plus optional Vercel previews
allowed_env = os.getenv(
    "FRONTEND_ORIGINS",
    "https://attendencefrontend.vercel.app,http://localhost:3000"
)
allowed = [o.strip() for o in allowed_env.split(",") if o.strip()]

CORS(
    app,
    resources={
        r"/qr/*": {
            # You can pass exact origins + a regex for previews
            "origins": allowed + [re.compile(r"^https://.*\.vercel\.app$")],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
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
