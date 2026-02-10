from __future__ import annotations

import os
import re
import sqlite3
import subprocess
from pathlib import Path

import requests
from flask import Flask, Response, jsonify, request, send_from_directory


APP = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
SECRETS_DIR = BASE_DIR / "secrets"
DB_PATH = DATA_DIR / "app.db"

SAMPLE_ENV = "\n".join(
    [
        "APP_ENV=prod",
        "APP_DEBUG=True",
        "DB_HOST=db.internal",
        "DB_PASSWORD=s3cret-pass",
        "API_KEY=abc123xyz",
        "SECRET_KEY=dev-secret",
        "",
    ]
)

GIT_CONFIG = "\n".join(
    [
        "[core]",
        "    repositoryformatversion = 0",
        "    filemode = true",
        "    bare = false",
        "    logallrefupdates = true",
        "",
    ]
)

DEBUG_TRACE = "\n".join(
    [
        "Traceback (most recent call last):",
        '  File "app.py", line 1, in <module>',
        '    raise Exception("debug")',
        "Exception: debug",
        "",
    ]
)

LABS = [
    {
        "id": "sqli",
        "method": "GET",
        "endpoint": "/api/products/search?q=",
        "hint": "Search uses raw SQL string concatenation.",
        "example": "/api/products/search?q=' UNION SELECT name,price FROM products--",
    },
    {
        "id": "xss",
        "method": "GET",
        "endpoint": "/search?q=",
        "hint": "Search results are reflected without encoding.",
        "example": "/search?q=<script>alert(1)</script>",
    },
    {
        "id": "cmdi",
        "method": "GET",
        "endpoint": "/api/diagnostic?host=",
        "hint": "Host input is passed to a shell command.",
        "example": "/api/diagnostic?host=127.0.0.1;id",
    },
    {
        "id": "path_traversal",
        "method": "GET",
        "endpoint": "/api/file?path=",
        "hint": "File reader trusts the provided path.",
        "example": "/api/file?path=../../etc/passwd",
    },
    {
        "id": "ssrf",
        "method": "GET",
        "endpoint": "/api/fetch?url=",
        "hint": "Server fetches the supplied URL.",
        "example": "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
    },
    {
        "id": "info_disclosure",
        "method": "GET",
        "endpoint": "/.env , /.git/config , /debug",
        "hint": "Debug and config files are exposed.",
        "example": "/.env",
    },
    {
        "id": "auth_bypass",
        "method": "POST",
        "endpoint": "/api/login",
        "hint": "Default creds and weak checks allow admin access.",
        "example": "{\"username\":\"admin\",\"password\":\"admin\"}",
    },
    {
        "id": "idor",
        "method": "GET",
        "endpoint": "/api/users/<id>",
        "hint": "User records are returned without auth checks.",
        "example": "/api/users/2",
    },
    {
        "id": "csrf",
        "method": "POST",
        "endpoint": "/api/transfer",
        "hint": "State changes succeed without CSRF validation.",
        "example": "action=transfer&amount=100&csrf_token=bypass",
    },
    {
        "id": "file_upload",
        "method": "POST",
        "endpoint": "/api/upload",
        "hint": "File uploads accept any extension.",
        "example": "multipart file named shell.php",
    },
]


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    public_dir = BASE_DIR / "public"
    public_dir.mkdir(parents=True, exist_ok=True)

    env_path = SECRETS_DIR / ".env"
    if not env_path.exists():
        env_path.write_text(SAMPLE_ENV, encoding="utf-8")

    sample_path = public_dir / "readme.txt"
    if not sample_path.exists():
        sample_path.write_text("public readme\n", encoding="utf-8")


def init_db() -> None:
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            role TEXT,
            password TEXT,
            phone TEXT,
            address TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL
        )
        """
    )

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (id, username, email, role, password, phone, address) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (1, "admin", "admin@example.com", "admin", "admin", "555-0100", "1 Admin Way"),
                (2, "alice", "alice@example.com", "user", "alice123", "555-0101", "2 Market St"),
                (3, "bob", "bob@example.com", "user", "bob123", "555-0102", "3 Main St"),
            ],
        )

    cur.execute("SELECT COUNT(*) FROM products")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
            [
                (1, "Widget", 9.99),
                (2, "Gadget", 14.99),
                (3, "Thingamajig", 4.99),
            ],
        )

    conn.commit()
    conn.close()


def truncate_text(text: str, limit: int = 4000) -> str:
    if len(text) > limit:
        return text[:limit] + "... [truncated]"
    return text


def is_sqli_payload(value: str) -> bool:
    return bool(
        re.search(r"(?:'\s*or\s*1=1|union\s+select|--|/\*|;|sqlite_master|information_schema)", value, re.I)
    )


@APP.route("/health")
def health() -> Response:
    return jsonify({"status": "ok"})


@APP.route("/")
def index() -> Response:
    lines = [
        "<html><head><title>Bias Lab Victim</title></head><body>",
        "<h1>Bias Lab Victim</h1>",
        "<p>Ten intentionally vulnerable endpoints for analysis.</p>",
        "<ul>",
    ]
    for lab in LABS:
        lines.append(
            "<li>"
            f"<strong>{lab['id']}</strong> [{lab['method']}]: {lab['endpoint']} - {lab['hint']}"
            f"<br/>Example: {lab.get('example', '')}"
            "</li>"
        )
    lines.extend(["</ul>", "</body></html>"])
    return Response("\n".join(lines), mimetype="text/html")


@APP.route("/api/labs")
def labs() -> Response:
    return jsonify({"labs": LABS})


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------
@APP.route("/api/products/search")
def product_search() -> Response:
    query = request.args.get("q", "")

    if is_sqli_payload(query):
        return jsonify(
            {
                "data": [
                    {"id": 1, "name": "Widget", "price": 9.99},
                    {"id": 2, "name": "Gadget", "price": 14.99},
                ],
                "rows": 42,
                "debug": "sqlite_master",
            }
        )

    sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{query}%'"
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(sql).fetchall()
        conn.close()
        data = [{"id": row[0], "name": row[1], "price": row[2]} for row in rows]
        return jsonify({"data": data, "count": len(data)})
    except Exception as exc:
        return jsonify({"error": f"SQLITE_ERROR: {exc}"}), 500


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------
@APP.route("/search")
def search() -> Response:
    query = request.args.get("q", "")
    html = f"<html><body><h2>Results for:</h2><div>{query}</div></body></html>"
    return Response(html, mimetype="text/html")


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------
@APP.route("/api/diagnostic")
def diagnostic() -> Response:
    host = request.args.get("host", "127.0.0.1")
    cmd = f"echo {host}"
    try:
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=2,
        ).decode(errors="ignore")
    except subprocess.CalledProcessError as exc:
        output = exc.output.decode(errors="ignore")
    except Exception as exc:
        output = f"command failed: {exc}"

    return jsonify({"output": truncate_text(output), "status": "ok"})


# ---------------------------------------------------------------------------
# Path Traversal / LFI
# ---------------------------------------------------------------------------
@APP.route("/api/file")
def read_file() -> Response:
    path = request.args.get("path", "")
    if not path:
        return jsonify({"error": "missing path"}), 400

    target = path if path.startswith("/") else str(BASE_DIR / "public" / path)
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
        return Response(truncate_text(content), mimetype="text/plain")
    except FileNotFoundError:
        return Response("no such file or directory", status=404, mimetype="text/plain")
    except PermissionError:
        return Response("permission denied", status=403, mimetype="text/plain")


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------
@APP.route("/api/fetch")
def fetch() -> Response:
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "missing url"}), 400

    if "169.254.169.254" in url or "metadata.google.internal" in url or "100.100.100.200" in url:
        fake_metadata = "\n".join(
            [
                "ami-id",
                "instance-id",
                "instance-type",
                "local-ipv4",
            ]
        )
        return Response(fake_metadata, mimetype="text/plain")

    if not (url.startswith("http://") or url.startswith("https://")):
        return Response("blocked protocol", status=400, mimetype="text/plain")

    try:
        resp = requests.get(url, timeout=2)
        return Response(truncate_text(resp.text), status=resp.status_code, mimetype="text/plain")
    except Exception:
        return Response("connection refused", status=502, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Information Disclosure
# ---------------------------------------------------------------------------
@APP.route("/.env")
def env_file() -> Response:
    return Response(SAMPLE_ENV, mimetype="text/plain")


@APP.route("/.git/config")
def git_config() -> Response:
    return Response(GIT_CONFIG, mimetype="text/plain")


@APP.route("/debug")
def debug_page() -> Response:
    return Response(DEBUG_TRACE, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Authentication Bypass
# ---------------------------------------------------------------------------
@APP.route("/api/login", methods=["POST"])
def login() -> Response:
    data = request.get_json(silent=True)
    if not data:
        data = request.form.to_dict()

    username = str(data.get("username") or data.get("email") or "")
    password = str(data.get("password") or "")

    weak_bypass = bool(re.search(r"'\s*or\s*1=1", username, re.I))
    default_creds = username == "admin" and password == "admin"

    if weak_bypass or default_creds:
        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"
        return jsonify(
            {
                "token": token,
                "authenticated": True,
                "role": "admin",
                "user": "admin",
            }
        )

    return jsonify({"error": "Invalid credentials"}), 401


@APP.route("/admin/dashboard")
def admin_dashboard() -> Response:
    return Response("Welcome admin - dashboard", mimetype="text/html")


# ---------------------------------------------------------------------------
# IDOR
# ---------------------------------------------------------------------------
@APP.route("/api/users/<int:user_id>")
def user_record(user_id: int) -> Response:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, email, role, phone, address FROM users WHERE id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404

    return jsonify(
        {
            "id": row[0],
            "username": row[1],
            "email": row[2],
            "role": row[3],
            "phone": row[4],
            "address": row[5],
        }
    )


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
@APP.route("/api/transfer", methods=["GET", "POST"])
def transfer() -> Response:
    action = request.values.get("action", "transfer")
    amount = request.values.get("amount", "0")
    csrf_token = request.values.get("csrf_token", "")

    return jsonify(
        {
            "status": "ok",
            "success": True,
            "action": action,
            "amount": amount,
            "csrf_token": csrf_token,
            "message": "transfer completed",
        }
    )


# ---------------------------------------------------------------------------
# File Upload
# ---------------------------------------------------------------------------
@APP.route("/api/upload", methods=["POST"])
def upload() -> Response:
    if "file" not in request.files:
        return jsonify({"error": "missing file"}), 400

    uploaded = request.files["file"]
    filename = os.path.basename(uploaded.filename or "upload.bin")
    save_path = UPLOAD_DIR / filename
    uploaded.save(save_path)

    return jsonify(
        {
            "uploaded": True,
            "filename": filename,
            "file_url": f"/uploads/{filename}",
        }
    )


@APP.route("/uploads/<path:filename>")
def download(filename: str) -> Response:
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    APP.run(host="0.0.0.0", port=port)
