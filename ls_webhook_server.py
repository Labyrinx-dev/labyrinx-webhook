"""
Lemon Squeezy Webhook Server — auto-generate license keys for Labyrinx subscriptions.

Handles LS subscription webhooks:
  - subscription_created      -> generate license key
  - subscription_payment_success -> renew license key
  - subscription_cancelled    -> log (key stays valid until expiry)
  - subscription_expired      -> log

Deploy on Render:
  Start command: python ls_webhook_server.py --port $PORT --secret-key _license_secret.key
"""

import hashlib, hmac, json, os, sys, sqlite3, time, logging
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ls_webhook")

# ── Configuration ──────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "ls_orders.db"
WEBHOOK_SECRET = os.environ.get("LS_WEBHOOK_SECRET", "")  # Set in Render env vars
LICENSE_SECRET_PATH = None  # Set via CLI arg

# Map LS variant IDs to Labyrinx tiers
LS_VARIANT_TIER = {
    # "variant_id_from_ls": "labyrinx_tier",
}

TIER_EXPIRY = {
    "pro": 365,
    "enterprise": 365,
}


# ── Database ───────────────────────────────────────────────────────────
def init_db():
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ls_order_id TEXT UNIQUE NOT NULL,
                customer_name TEXT NOT NULL,
                customer_email TEXT NOT NULL,
                tier TEXT NOT NULL,
                product_name TEXT,
                variant_name TEXT,
                license_key TEXT NOT NULL,
                expiry_ts INTEGER NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webhook_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                ls_order_id TEXT,
                status TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()
    logger.info("Database ready")


# ── License Generation (self-contained, no Labyrinx imports) ──────────
def load_license_secret():
    """Load the 16-byte license secret from env var or file."""
    # 1. Environment variable (Render: set LICENSE_SECRET=base64...)
    env_secret = os.environ.get("LICENSE_SECRET", "")
    if env_secret:
        import base64 as _b64
        try:
            return _b64.b64decode(env_secret)
        except Exception:
            pass
    # 2. File (for local testing)
    if LICENSE_SECRET_PATH:
        p = Path(LICENSE_SECRET_PATH)
        if p.is_file() and p.stat().st_size == 16:
            return p.read_bytes()
    logger.error("License secret not found. Set LICENSE_SECRET env var.")
    return None


def generate_license(secret, customer_name, tier, expiry_days, hwid=""):
    """Generate a Labyrinx license key.

    Format: base64(customer|timestamp|tier[|HWID]).hex(HMAC-SHA256[:16])
    Compatible with Labyrinx LicenseManager (BCrypt HMAC = Python hmac).
    """
    import base64 as _b64
    safe = customer_name.strip()[:32]
    expiry_ts = int(time.time()) + expiry_days * 86400
    payload = f"{safe}|{expiry_ts}|{tier.strip().lower()}"
    if hwid:
        payload += f"|{hwid.strip().upper()}"
    payload_b64 = _b64.b64encode(payload.encode()).decode()
    sig = hmac.new(secret, payload_b64.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload_b64}.{sig}"


# ── Webhook Verification ───────────────────────────────────────────────
def verify_signature(payload: bytes, signature: str) -> bool:
    if not WEBHOOK_SECRET:
        logger.warning("Webhook secret not set — skipping verification")
        return True
    expected = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Tier Mapping ───────────────────────────────────────────────────────
def map_tier(variant_id: str) -> str:
    tier = LS_VARIANT_TIER.get(str(variant_id))
    if tier:
        return tier
    logger.warning("Unknown variant %s — defaulting to pro", variant_id)
    return "pro"


# ── Helpers ────────────────────────────────────────────────────────────
def log_webhook(event_type, ls_order_id, status, detail=""):
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO webhook_log (event_type, ls_order_id, status, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_type, ls_order_id, status, detail, datetime.now().isoformat()))
        conn.commit()


# ── Webhook Endpoint ───────────────────────────────────────────────────
@app.route("/webhook/ls", methods=["POST"])
def handle_webhook():
    payload = request.get_data()
    signature = request.headers.get("X-Signature", "")

    if not verify_signature(payload, signature):
        logger.warning("Invalid webhook signature from %s", request.remote_addr)
        return jsonify({"error": "invalid signature"}), 401

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return jsonify({"error": "invalid JSON"}), 400

    event_type = data.get("meta", {}).get("event_name", "unknown")
    event_data = data.get("data", {})
    attrs = event_data.get("attributes", {})

    LICENSE_EVENTS = {"subscription_created", "subscription_payment_success"}
    STATUS_EVENTS = {"subscription_cancelled", "subscription_expired",
                     "subscription_payment_failed"}

    if event_type not in (LICENSE_EVENTS | STATUS_EVENTS):
        log_webhook(event_type, "", "ignored", str(event_type))
        return jsonify({"status": "ignored"}), 200

    order_id = str(attrs.get("order_id", event_data.get("id", "")))
    customer_name = attrs.get("user_name", "Customer")
    customer_email = attrs.get("user_email", "")
    product_name = attrs.get("product_name", "")
    variant_name = attrs.get("variant_name", "")
    variant_id = str(attrs.get("variant_id", ""))

    if not customer_email:
        log_webhook(event_type, order_id, "error", "Missing email")
        return jsonify({"error": "missing customer email"}), 400

    if event_type in STATUS_EVENTS:
        log_webhook(event_type, order_id, "recorded",
                    f"{event_type} for {customer_email}")
        return jsonify({"status": "recorded", "event": event_type}), 200

    # Generate/renew license
    tier = map_tier(variant_id)
    expiry_days = TIER_EXPIRY.get(tier, 365)
    secret = load_license_secret()
    if not secret:
        return jsonify({"error": "license secret not configured"}), 500

    license_key = generate_license(secret, customer_name, tier, expiry_days)
    if not license_key:
        return jsonify({"error": "license generation failed"}), 500

    expiry_ts = int(time.time()) + expiry_days * 86400

    with sqlite3.connect(str(DB_PATH)) as conn:
        existing = conn.execute(
            "SELECT id FROM orders WHERE ls_order_id = ?", (order_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE orders SET license_key=?, expiry_ts=?, status='active', "
                "created_at=? WHERE ls_order_id=?",
                (license_key, expiry_ts, datetime.now().isoformat(), order_id))
        else:
            conn.execute(
                "INSERT INTO orders (ls_order_id, customer_name, customer_email, "
                "tier, product_name, variant_name, license_key, expiry_ts, "
                "status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)",
                (order_id, customer_name, customer_email, tier, product_name,
                 variant_name, license_key, expiry_ts, datetime.now().isoformat()))
        conn.commit()

    log_webhook(event_type, order_id, "success",
                f"{'Renewed' if existing else 'Generated'} for {customer_email} ({tier})")

    logger.info("%s LICENSE: %s <%s> tier=%s",
                "RENEWED" if existing else "NEW",
                customer_name, customer_email, tier)

    return jsonify({
        "status": "success",
        "license_key": license_key,
        "tier": tier,
        "expiry_days": expiry_days,
        "customer": customer_name,
        "email": customer_email,
    }), 200


# ── Management ─────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    with sqlite3.connect(str(DB_PATH)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    return jsonify({"status": "ok", "licenses_issued": count})


@app.route("/licenses", methods=["GET"])
def list_licenses():
    with sqlite3.connect(str(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT id, customer_name, customer_email, tier, license_key, "
            "expiry_ts, status, created_at FROM orders ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return jsonify([{
        "id": r[0], "customer": r[1], "email": r[2], "tier": r[3],
        "license_key": r[4], "expiry": r[5], "status": r[6], "created": r[7],
    } for r in rows])


@app.route("/license/<ls_order_id>", methods=["GET"])
def get_license(ls_order_id):
    with sqlite3.connect(str(DB_PATH)) as conn:
        row = conn.execute(
            "SELECT license_key FROM orders WHERE ls_order_id = ?",
            (ls_order_id,)
        ).fetchone()
    if row:
        return jsonify({"license_key": row[0]})
    return jsonify({"error": "not found"}), 404


# ── CLI ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Labyrinx LS Webhook Server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--secret-key", required=True,
                        help="Path to 16-byte license secret")
    parser.add_argument("--webhook-secret",
                        help="LS signing secret (or set LS_WEBHOOK_SECRET env var)")
    args = parser.parse_args()

    LICENSE_SECRET_PATH = args.secret_key
    if args.webhook_secret:
        WEBHOOK_SECRET = args.webhook_secret

    init_db()
    logger.info("Starting on %s:%d", args.host, args.port)
    logger.info("License secret: %s", "OK" if load_license_secret() else "MISSING")
    logger.info("Webhook secret: %s",
                "configured" if WEBHOOK_SECRET else "NOT SET")

    app.run(host=args.host, port=args.port, debug=False)
