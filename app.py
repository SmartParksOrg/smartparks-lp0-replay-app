#!/usr/bin/env python3
import os
import binascii
import secrets
import time
import json
import socket
import base64
import datetime
import io
import csv
import subprocess
import html
import threading
import urllib.parse
from flask import Flask, request, render_template_string, url_for, send_file, redirect, jsonify, session, has_request_context
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import make_test_log

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
MAX_CONTENT_MB = int(os.environ.get("MAX_CONTENT_MB", "50"))
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_MB * 1024 * 1024


def env_flag(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


PUBLIC_MODE = env_flag("PUBLIC_MODE", False)
DECODER_UPLOADS_ENABLED = env_flag("DECODER_UPLOADS_ENABLED", not PUBLIC_MODE)
DECODER_FILE_EXECUTION_ENABLED = env_flag("DECODER_FILE_EXECUTION_ENABLED", not PUBLIC_MODE)
USER_MAX_LOGS = int(os.environ.get("USER_MAX_LOGS", "50"))
USER_MAX_LOG_MB = int(os.environ.get("USER_MAX_LOG_MB", "200"))
USER_MAX_LOG_BYTES = USER_MAX_LOG_MB * 1024 * 1024
AUDIT_LOG_MAX_MB = int(os.environ.get("AUDIT_LOG_MAX_MB", "5"))
AUDIT_LOG_MAX_BYTES = AUDIT_LOG_MAX_MB * 1024 * 1024
AUDIT_LOG_BACKUPS = int(os.environ.get("AUDIT_LOG_BACKUPS", "5"))
SESSION_COOKIE_SECURE = env_flag("SESSION_COOKIE_SECURE", PUBLIC_MODE)
SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
TRUST_PROXY = env_flag("TRUST_PROXY", False)
RATE_LIMIT_STATE = {}
RATE_LIMITS = {
    "scan": (int(os.environ.get("RATE_LIMIT_SCAN_PER_MIN", "12")), 60),
    "replay": (int(os.environ.get("RATE_LIMIT_REPLAY_PER_MIN", "6")), 60),
    "decode": (int(os.environ.get("RATE_LIMIT_DECODE_PER_MIN", "6")), 60),
    "generate": (int(os.environ.get("RATE_LIMIT_GENERATE_PER_MIN", "6")), 60),
    "decoder_upload": (int(os.environ.get("RATE_LIMIT_DECODER_UPLOAD_PER_MIN", "6")), 60),
}
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
SCAN_CACHE = {}
SCAN_CACHE_TTL = 30 * 60
DECODE_CACHE = {}
DECODE_CACHE_TTL = 30 * 60
REPLAY_CACHE = {}
REPLAY_CACHE_TTL = 30 * 60
REPLAY_LOCK = threading.Lock()
REPLAY_RXPK_OVERRIDES = {
    "freq": 868.1,
    "chan": 0,
    "rfch": 0,
    "stat": 1,
    "modu": "LORA",
    "datr": "SF9BW125",
    "codr": "4/5",
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DECODER_DIR = os.path.join(DATA_DIR, "decoders")
DECODE_RESULTS_DIR = os.path.join(DATA_DIR, "decoded_results")
BUILTIN_DECODER_DIR = os.path.join(BASE_DIR, "decoders")
FIELD_META_PATH = os.path.join(BASE_DIR, "field-meta.json")
CREDENTIALS_PATH = os.path.join(DATA_DIR, "credentials.json")
UPLOAD_INDEX_PATH = os.path.join(DATA_DIR, "uploads.json")
DECODE_RESULTS_INDEX_PATH = os.path.join(DATA_DIR, "decoded_results.json")
DECODE_PROGRESS = {}
AUTH_PATH = os.path.join(DATA_DIR, "auth.json")
AUDIT_LOG_PATH = os.path.join(DATA_DIR, "audit.log")
CSRF_SESSION_KEY = "_csrf_token"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

class AppUser(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


def get_csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def get_csrf_input():
    token = html.escape(get_csrf_token())
    return f"<input type=\"hidden\" name=\"csrf_token\" value=\"{token}\">"


def validate_csrf():
    form_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    session_token = session.get(CSRF_SESSION_KEY, "")
    if not form_token or not session_token:
        return False
    return secrets.compare_digest(form_token, session_token)


@app.before_request
def enforce_csrf():
    if request.method != "POST":
        return None
    if request.endpoint == "static":
        return None
    if not validate_csrf():
        return "Invalid CSRF token.", 400


@app.errorhandler(413)
def request_entity_too_large(error):
    return "Upload too large.", 413


def get_user_id():
    if current_user and current_user.is_authenticated:
        return current_user.id
    return "anonymous"


def format_bytes(value):
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.1f} MB"


def check_rate_limit(bucket, user_id):
    limit, window = RATE_LIMITS.get(bucket, (0, 0))
    if limit <= 0 or window <= 0:
        return True, 0
    now = time.time()
    cutoff = now - window
    key = f"{bucket}:{user_id}"
    timestamps = RATE_LIMIT_STATE.get(key, [])
    timestamps = [stamp for stamp in timestamps if stamp > cutoff]
    if len(timestamps) >= limit:
        retry_after = int(window - (now - timestamps[0]))
        return False, max(retry_after, 1)
    timestamps.append(now)
    RATE_LIMIT_STATE[key] = timestamps
    return True, 0


def get_user_log_usage(user_id):
    count = 0
    total_bytes = 0
    for entry in list_stored_logs():
        if entry.get("owner") != user_id:
            continue
        count += 1
        size = entry.get("size")
        if size is None:
            path = entry.get("path", "")
            if path and os.path.exists(path):
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
        total_bytes += int(size or 0)
    return count, total_bytes


def check_user_log_quota(user_id, new_bytes=None):
    count, total_bytes = get_user_log_usage(user_id)
    if USER_MAX_LOGS > 0 and count >= USER_MAX_LOGS:
        return False, f"Log quota exceeded (max {USER_MAX_LOGS} logs)."
    if USER_MAX_LOG_BYTES > 0:
        if new_bytes is None:
            if total_bytes >= USER_MAX_LOG_BYTES:
                return False, f"Storage quota exceeded (max {format_bytes(USER_MAX_LOG_BYTES)})."
        elif total_bytes + int(new_bytes) > USER_MAX_LOG_BYTES:
            return False, f"Storage quota exceeded (max {format_bytes(USER_MAX_LOG_BYTES)})."
    return True, ""


def enforce_user_log_quota_after_store(user_id, entry):
    if not entry:
        return True, ""
    count, total_bytes = get_user_log_usage(user_id)
    if USER_MAX_LOGS > 0 and count > USER_MAX_LOGS:
        delete_stored_log(entry["id"])
        return False, f"Log quota exceeded (max {USER_MAX_LOGS} logs)."
    if USER_MAX_LOG_BYTES > 0 and total_bytes > USER_MAX_LOG_BYTES:
        delete_stored_log(entry["id"])
        return False, f"Storage quota exceeded (max {format_bytes(USER_MAX_LOG_BYTES)})."
    return True, ""


def audit_log(event, details=None):
    entry = {
        "ts": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "event": event,
        "user": get_user_id(),
    }
    if has_request_context():
        entry["ip"] = request.headers.get("X-Forwarded-For", request.remote_addr)
        entry["path"] = request.path
        entry["method"] = request.method
    if details:
        entry["details"] = details
    try:
        ensure_data_dirs()
        rotate_needed = False
        if AUDIT_LOG_MAX_BYTES > 0 and os.path.exists(AUDIT_LOG_PATH):
            try:
                rotate_needed = os.path.getsize(AUDIT_LOG_PATH) >= AUDIT_LOG_MAX_BYTES
            except OSError:
                rotate_needed = False
        if rotate_needed:
            for idx in range(AUDIT_LOG_BACKUPS, 0, -1):
                src = f"{AUDIT_LOG_PATH}.{idx}"
                dst = f"{AUDIT_LOG_PATH}.{idx + 1}"
                if os.path.exists(src):
                    if idx >= AUDIT_LOG_BACKUPS:
                        os.remove(src)
                    else:
                        os.replace(src, dst)
            os.replace(AUDIT_LOG_PATH, f"{AUDIT_LOG_PATH}.1")
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError:
        pass


def get_auth_config():
    ensure_data_dirs()
    config = load_json_file(AUTH_PATH, {})
    if config and "users" in config:
        return config
    if config and "username" in config and "password_hash" in config:
        users = {
            config["username"]: {
                "password_hash": config["password_hash"],
                "must_change": config.get("must_change", False),
                "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
        }
        config = {"users": users}
        save_json_file(AUTH_PATH, config)
        return config
    config = {
        "users": {
            "admin": {
                "password_hash": generate_password_hash("admin"),
                "must_change": True,
                "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
        }
    }
    save_json_file(AUTH_PATH, config)
    return config


def get_users():
    return get_auth_config().get("users", {})


def save_users(users):
    config = get_auth_config()
    config["users"] = users
    save_json_file(AUTH_PATH, config)


def set_auth_password(username, password):
    users = get_users()
    entry = users.get(username)
    if not entry:
        return False
    entry["password_hash"] = generate_password_hash(password)
    entry["must_change"] = False
    users[username] = entry
    save_users(users)
    return True


def verify_credentials(username, password):
    config = get_auth_config()
    users = config.get("users", {})
    entry = users.get(username)
    if not entry:
        return False
    return check_password_hash(entry["password_hash"], password)


@login_manager.user_loader
def load_user(user_id):
    config = get_auth_config()
    if user_id in config.get("users", {}):
        return AppUser(user_id)
    return None


STYLE_BLOCK = """
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
  <style>
    :root {
      color-scheme: light;
      font-family: "Inter", "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      --bg: linear-gradient(135deg, #eef2ff, #fdf2f8);
      --card-bg: #fff;
      --card-shadow: rgba(15, 23, 42, 0.08);
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --text-muted: #6b7280;
      --border: #e5e7eb;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: var(--bg);
      min-height: 100vh;
      display: flex;
      align-items: stretch;
      justify-content: stretch;
      padding: 1.5rem 2.5rem;
      color: #0f172a;
    }

    .outer-column {
      width: 100%;
      max-width: 1200px;
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
      align-items: stretch;
      margin: 0 auto;
      position: relative;
    }

    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.5rem 0.25rem 0;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .brand img {
      width: 52px;
      height: auto;
    }

    .brand-title {
      font-weight: 700;
      font-size: 1.05rem;
      letter-spacing: 0.01em;
    }

    .brand-subtitle {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    .menu-toggle {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 40px;
      height: 40px;
      border: 1px solid var(--border);
      background: #fff;
      border-radius: 12px;
      padding: 0;
      cursor: pointer;
      font-weight: 600;
      color: var(--accent);
      transition: border-color 0.2s, background 0.2s;
    }

    .menu-toggle:hover {
      background: #f8fafc;
      border-color: var(--accent);
    }

    .top-actions {
      display: inline-flex;
      align-items: center;
      gap: 0.6rem;
    }

    .user-pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 0.35rem 0.8rem;
      background: #f1f5f9;
      color: #475569;
      font-size: 0.85rem;
      font-weight: 600;
    }

    .menu-toggle span {
      display: block;
    }

    .menu-toggle .menu-label {
      display: none;
    }

    .menu-toggle .bar {
      width: 18px;
      height: 2px;
      background: #0f172a;
      border-radius: 999px;
      transition: transform 0.2s, opacity 0.2s;
    }

    .menu-toggle .bars {
      display: inline-flex;
      flex-direction: column;
      gap: 3px;
    }

    .menu-toggle.open .bar:nth-child(1) {
      transform: translateY(5px) rotate(45deg);
    }

    .menu-toggle.open .bar:nth-child(2) {
      opacity: 0;
    }

    .menu-toggle.open .bar:nth-child(3) {
      transform: translateY(-5px) rotate(-45deg);
    }

    .menu-panel {
      position: absolute;
      top: 4.5rem;
      right: 1.5rem;
      z-index: 50;
      max-width: 520px;
      background: #fff;
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 20px 50px rgba(15, 23, 42, 0.12);
      padding: 0.75rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 0.35rem;
    }

    .menu-panel[hidden] {
      display: none;
    }

    .menu-link {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0.5rem 0.75rem;
      border-radius: 12px;
      text-decoration: none;
      color: #0f172a;
      font-weight: 600;
      border: 1px solid transparent;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
      gap: 0.4rem;
    }

    .menu-link .material-icons {
      font-size: 18px;
      line-height: 1;
    }

    .menu-toggle .material-icons {
      font-size: 18px;
      line-height: 1;
    }

    .page-title {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
    }

    .page-title .material-icons {
      font-size: 24px;
      line-height: 1;
      color: var(--accent);
    }

    .menu-link:hover {
      border-color: rgba(37, 99, 235, 0.4);
      background: rgba(37, 99, 235, 0.08);
      color: var(--accent-hover);
    }

    .menu-link.active {
      border-color: rgba(37, 99, 235, 0.6);
      background: rgba(37, 99, 235, 0.15);
      color: var(--accent);
    }

    .logo-card {
      width: 100%;
      background: transparent;
      border-radius: 24px;
      box-shadow: none;
      border: none;
      padding: 0.375rem;
      text-align: center;
    }

    .logo-card img {
      max-width: 120px;
      width: 25%;
      height: auto;
    }

    .card {
      width: 100%;
      background: var(--card-bg);
      border-radius: 24px;
      box-shadow: 0 24px 70px var(--card-shadow);
      padding: 3rem;
      border: 1px solid var(--border);
    }

    h1 {
      margin: 0 0 0.4rem;
      font-size: 2.05rem;
    }

    .subtitle {
      margin: 0 0 2rem;
      color: var(--text-muted);
      font-size: 1rem;
    }

    form {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    label {
      font-weight: 600;
      margin-bottom: 0.4rem;
    }

    label + input,
    label + select {
      margin-top: 0.35rem;
    }

    .field-group {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }

    .field-header {
      font-weight: 600;
    }

    .devaddr-label {
      color: var(--accent);
    }

    .field-controls {
      position: relative;
      display: flex;
      align-items: center;
      min-width: 0;
    }

    .input-with-actions {
      flex: 1;
      min-width: 0;
    }

    .field-tools {
      position: absolute;
      right: 0.4rem;
      display: inline-flex;
      gap: 0.3rem;
      background: #fff;
      padding-left: 0.3rem;
    }

    .icon-button {
      border: 1px solid var(--border);
      background: #fff;
      border-radius: 8px;
      width: 32px;
      height: 32px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 0.85rem;
      color: var(--accent);
      cursor: pointer;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
    }

    .icon-button .material-icons {
      font-size: 18px;
      line-height: 1;
    }

    .icon-button:hover {
      border-color: var(--accent);
      background: rgba(37, 99, 235, 0.05);
    }

    .toggle-visibility {
      position: absolute;
      right: 0.4rem;
      border: 1px solid var(--border);
      background: #fff;
      border-radius: 8px;
      width: 32px;
      height: 32px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 0.9rem;
      color: var(--accent);
      cursor: pointer;
      transition: border-color 0.2s, color 0.2s, background 0.2s;
    }

    .toggle-visibility .material-icons {
      font-size: 18px;
      line-height: 1;
    }

    .toggle-visibility:hover {
      border-color: var(--accent);
      background: rgba(37, 99, 235, 0.05);
    }

    .inline-action {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.35rem 0.75rem;
      border-radius: 999px;
      background: rgba(37, 99, 235, 0.12);
      color: var(--accent);
      font-size: 0.85rem;
      text-decoration: none;
      border: 1px solid rgba(37, 99, 235, 0.25);
      transition: background 0.2s, color 0.2s, border-color 0.2s;
    }

    .inline-action:hover {
      background: rgba(37, 99, 235, 0.18);
      color: var(--accent-hover);
      border-color: rgba(37, 99, 235, 0.4);
    }

    .inline-action span {
      font-weight: 600;
    }

    .inline-action-row {
      margin-bottom: 0.5rem;
    }

    .logfile-options {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 0.85rem;
      margin-top: 0.25rem;
    }

    .logfile-option {
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1rem;
      background: #f8fafc;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      height: 100%;
    }

    .logfile-option h3 {
      margin: 0;
      font-size: 1.05rem;
    }

    .logfile-option .hint {
      margin: 0;
    }

    .option-actions {
      margin-top: auto;
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .option-actions .secondary-button {
      width: 100%;
      justify-content: center;
      text-align: center;
    }

    .next-steps {
      margin-top: 1.5rem;
      padding: 1.25rem;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: #f8fafc;
    }

    .next-steps h2 {
      margin: 0 0 0.6rem;
      font-size: 1.1rem;
    }

    .action-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.75rem;
    }

    input[type=text],
    input[type=number],
    input[type=file],
    input[type=datetime-local],
    input[type=password],
    select {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.65rem 0.75rem;
      font-size: 1rem;
      transition: border-color 0.2s, box-shadow 0.2s;
    }

    input[type=text]:focus,
    input[type=number]:focus,
    input[type=file]:focus,
    input[type=datetime-local]:focus,
    input[type=password]:focus,
    select:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
    }

    input[type=password] {
      font-family: inherit;
      letter-spacing: normal;
    }

    .key-input {
      font-family: "IBM Plex Mono", "SFMono-Regular", "Menlo", monospace;
      font-size: 0.72rem;
      letter-spacing: -0.01em;
      font-variant-ligatures: none;
    }

    .hint {
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-top: 0.35rem;
    }

    .simple-list {
      margin: 0.5rem 0 0;
      padding-left: 1.2rem;
      color: #0f172a;
    }

    .simple-list li {
      margin: 0.25rem 0;
    }

    .decoder-list {
      list-style: none;
      padding: 0;
      margin: 0.75rem 0 0;
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }

    .file-list {
      display: flex;
      flex-direction: column;
      gap: 0.7rem;
      margin-top: 0.6rem;
    }

    .file-entry {
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #f8fafc;
      overflow: hidden;
    }

    .file-entry summary {
      list-style: none;
      cursor: pointer;
      padding: 0.75rem 0.9rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      font-weight: 600;
      color: #0f172a;
    }

    .file-entry summary::-webkit-details-marker {
      display: none;
    }

    .file-entry[open] summary {
      border-bottom: 1px solid var(--border);
      background: #fff;
    }

    .file-summary {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      flex-wrap: wrap;
    }

    .file-meta {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-weight: 500;
    }

    .file-body {
      padding: 0.75rem 0.9rem;
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }

    .file-controls {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.6rem;
      align-items: center;
      margin-top: 0.5rem;
    }

    .decoder-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      padding: 0.6rem 0.75rem;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #f8fafc;
    }

    .decoder-link {
      color: #0f172a;
      text-decoration: none;
      font-weight: 600;
      word-break: break-all;
    }

    .decoder-link:hover {
      color: var(--accent-hover);
    }

    .decoder-meta {
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-left: 0.5rem;
    }

    .decoder-actions {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }

    .file-actions {
      display: inline-flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.4rem;
    }

    .file-actions-stack {
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 0.5rem;
    }

    .saved-results {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      margin-top: 0.5rem;
    }

    .saved-entry {
      display: inline-flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.4rem;
    }

    .saved-label {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-weight: 600;
    }

    .code-block {
      background: #0f172a;
      color: #e2e8f0;
      padding: 1rem;
      border-radius: 12px;
      font-family: "IBM Plex Mono", "SFMono-Regular", "Menlo", monospace;
      font-size: 0.85rem;
      line-height: 1.4;
      overflow: auto;
      max-height: 420px;
    }

    .scan-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.55);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      z-index: 80;
    }

    .scan-overlay[hidden] {
      display: none;
    }

    .scan-card {
      background: #fff;
      border-radius: 18px;
      padding: 1.75rem;
      width: min(560px, 95vw);
      box-shadow: 0 25px 70px rgba(15, 23, 42, 0.18);
      border: 1px solid var(--border);
    }

    .scan-card h2 {
      margin: 0 0 0.75rem;
      font-size: 1.3rem;
    }

    .scan-card .form-actions {
      margin-top: 1rem;
    }

    button {
      padding: 0.9rem 1.4rem;
      border-radius: 12px;
      border: none;
      font-size: 1rem;
      font-weight: 600;
      background: var(--accent);
      color: white;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
    }

    button:hover {
      background: var(--accent-hover);
    }

    button:active {
      transform: translateY(1px);
    }

    button:disabled {
      background: #94a3b8;
      cursor: not-allowed;
      transform: none;
    }

    .form-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.8rem;
      align-items: center;
    }

    .secondary-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.85rem 1.2rem;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--accent);
      font-weight: 600;
      text-decoration: none;
      gap: 0.45rem;
      transition: border-color 0.2s, color 0.2s;
    }

    .secondary-button:hover {
      background: #f8fafc;
      border-color: var(--accent);
      color: var(--accent-hover);
    }

    .secondary-button.icon-only {
      width: 40px;
      height: 40px;
      padding: 0;
      border-radius: 12px;
    }

    .danger-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 32px;
      height: 32px;
      border-radius: 8px;
      border: 1px solid #fecaca;
      background: #fee2e2;
      color: #b91c1c;
      cursor: pointer;
      transition: background 0.2s, border-color 0.2s;
    }

    .danger-button:hover {
      background: #fecaca;
      border-color: #fca5a5;
    }

    .danger-button.danger-text {
      width: auto;
      height: auto;
      padding: 0.85rem 1.2rem;
      font-size: 0.9rem;
      font-weight: 600;
      gap: 0.35rem;
    }

    .danger-button svg {
      width: 18px;
      height: 18px;
      display: block;
      fill: currentColor;
    }

    .stop-replay-button {
      background: #dc2626;
    }

    .stop-replay-button:hover {
      background: #b91c1c;
    }

    .start-replay-button,
    .resume-replay-button {
      background: #16a34a;
    }

    .start-replay-button:hover,
    .resume-replay-button:hover {
      background: #15803d;
    }

    .restart-replay-button {
      background: #f97316;
    }

    .restart-replay-button:hover {
      background: #ea580c;
    }

    .is-hidden {
      display: none;
    }

    .field-controls.key-controls {
      gap: 0.5rem;
    }

    .field-controls.key-controls .toggle-visibility {
      position: static;
    }

    .primary-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.85rem 1.4rem;
      border-radius: 12px;
      background: var(--accent);
      color: #fff;
      font-weight: 600;
      text-decoration: none;
      border: 1px solid transparent;
      gap: 0.45rem;
      transition: background 0.2s, transform 0.2s;
    }

    .primary-button .material-icons,
    .secondary-button .material-icons,
    .danger-button.danger-text .material-icons {
      font-size: 18px;
      line-height: 1;
    }

    .danger-button .material-icons {
      font-size: 18px;
      line-height: 1;
    }

    .primary-button:hover {
      background: var(--accent-hover);
      transform: translateY(-1px);
    }

    .form-actions button,
    .form-actions .secondary-button {
      flex: 1;
      min-width: 180px;
      justify-content: center;
      text-align: center;
    }

    .payload-examples {
      margin-top: 0.7rem;
      padding: 0.9rem;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #f8fafc;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .payload-examples label {
      margin: 0;
      font-weight: 600;
      font-size: 0.95rem;
      color: #0f172a;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      margin-bottom: 1rem;
    }

    .file-drop {
      border: 1px dashed var(--accent);
      border-radius: 14px;
      padding: 1.1rem;
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.08), rgba(37, 99, 235, 0.16));
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      cursor: pointer;
      transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    }

    .file-drop:hover {
      border-color: var(--accent);
      box-shadow: 0 14px 34px rgba(37, 99, 235, 0.14);
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.12), rgba(37, 99, 235, 0.2));
    }

    .file-drop.dragover {
      border-color: var(--accent);
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.16), rgba(37, 99, 235, 0.24));
    }

    .file-drop .file-text {
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
    }

    .file-drop .file-text strong {
      font-size: 1rem;
      color: var(--accent);
    }

    .file-drop .file-selected {
      color: var(--text-muted);
      font-size: 0.9rem;
      word-break: break-all;
    }

    .file-drop .choose-button {
      padding: 0.65rem 1rem;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #fff;
      font-weight: 600;
      color: var(--accent);
      transition: border-color 0.2s, color 0.2s;
    }

    .file-drop .choose-button:hover {
      border-color: var(--accent);
      color: var(--accent-hover);
    }

    @media (max-width: 540px) {
      body {
        padding: 1rem;
      }

      .card {
        padding: 2rem 1.5rem;
      }

      .card-header {
        flex-direction: column;
        align-items: flex-start;
      }
    }

    .result {
      border-radius: 12px;
      padding: 0.9rem 1.1rem;
      font-size: 0.95rem;
      line-height: 1.4;
    }

    .result.success {
      background: #ecfdf5;
      border: 1px solid #34d399;
      color: #065f46;
    }

    .result.error {
      background: #fef2f2;
      border: 1px solid #f87171;
      color: #7f1d1d;
    }

    .result.info {
      background: #eff6ff;
      border: 1px solid #93c5fd;
      color: #1e3a8a;
    }

    .replay-status {
      margin-top: 1rem;
    }

    .log-wrapper {
      width: 100%;
    }

    .loading-overlay {
      position: fixed;
      inset: 0;
      background: rgba(255, 255, 255, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 50;
    }

    .loading-overlay[hidden] {
      display: none;
    }

    .loading-card {
      background: #fff;
      border-radius: 18px;
      box-shadow: 0 20px 60px rgba(15, 23, 42, 0.18);
      padding: 24px 28px;
      display: flex;
      align-items: center;
      gap: 16px;
      color: #0f172a;
      font-weight: 600;
    }

    [data-decode-overlay] .loading-card {
      flex-direction: column;
      align-items: stretch;
      gap: 14px;
      width: min(520px, 90vw);
      padding: 28px 30px;
    }

    [data-decode-overlay] .progress-track {
      height: 14px;
      margin-top: 0;
      background: #e2e8f0;
    }

    [data-decode-overlay] .progress-fill {
      transition: width 0.25s ease-out, background 0.25s ease-out;
    }

    [data-decode-overlay] .progress-meta {
      font-size: 0.95rem;
      color: #334155;
    }

    [data-decode-overlay] .progress-percent {
      font-weight: 700;
      color: #1d4ed8;
    }

    .spinner {
      width: 32px;
      height: 32px;
      border: 4px solid rgba(15, 23, 42, 0.2);
      border-top-color: #2563eb;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .log-block {
      border-radius: 20px;
      border: 1px solid var(--border);
      background: #fff;
      box-shadow: 0 12px 40px rgba(15, 23, 42, 0.08);
      padding: 1.2rem 1.4rem;
      width: 100%;
    }

    .log-block summary {
      cursor: pointer;
      font-weight: 600;
      color: var(--accent);
      outline: none;
      font-size: 1.05rem;
    }

    .log-controls {
      display: flex;
      justify-content: flex-end;
      margin-bottom: 0.6rem;
      gap: 0.6rem;
      flex-wrap: wrap;
      font-size: 0.9rem;
    }

    .log-controls select {
      width: auto;
      padding: 0.35rem 0.6rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      font-size: 0.9rem;
    }

    .log-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      font-size: 0.9rem;
    }

    .log-table th,
    .log-table td {
      text-align: left;
      padding: 0.55rem;
      border-bottom: 1px solid var(--border);
    }

    .log-table.users-table th,
    .log-table.users-table td {
      white-space: nowrap;
      vertical-align: middle;
    }

    .key-grid.user-grid {
      grid-template-columns: minmax(200px, 1fr) minmax(200px, 1fr) minmax(220px, 1fr) 140px;
      align-items: end;
    }

    .users-password-row {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.35rem;
    }

    .users-password-row .secondary-button {
      width: auto;
      min-width: 0;
      padding: 0.85rem 1.2rem;
    }

    .log-table th {
      font-weight: 600;
      color: var(--text-muted);
      font-size: 0.85rem;
    }

    .log-table th button {
      background: none;
      border: none;
      color: inherit;
      font: inherit;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.2rem;
      padding: 0;
    }

    .log-table th button.sorted-asc::after {
      content: "▲";
      font-size: 0.7rem;
      color: var(--accent);
    }

    .log-table th button.sorted-desc::after {
      content: "▼";
      font-size: 0.7rem;
      color: var(--accent);
    }

    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.55);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      z-index: 90;
    }

    .modal-overlay[hidden] {
      display: none;
    }

    .modal-card {
      background: #fff;
      border-radius: 18px;
      padding: 1.75rem;
      width: min(520px, 92vw);
      box-shadow: 0 25px 70px rgba(15, 23, 42, 0.18);
      border: 1px solid var(--border);
    }

    .modal-card h2 {
      margin: 0 0 0.75rem;
      font-size: 1.3rem;
    }

    .modal-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.6rem;
      margin-top: 1rem;
      align-items: center;
    }

    .user-name {
      font-weight: 700;
    }

    .log-table tbody tr.ok td {
      color: #047857;
    }

    .log-table tbody tr.err td {
      color: #b91c1c;
    }

    .truncate-cell {
      max-width: 320px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      cursor: pointer;
    }

    .truncate-cell.expanded {
      white-space: pre-wrap;
      overflow: visible;
      text-overflow: unset;
      max-width: none;
      cursor: zoom-out;
    }

    .truncate-cell::after {
      content: " ⤢";
      color: var(--text-muted);
      font-size: 0.75rem;
    }

    .truncate-cell.expanded::after {
      content: " ⤡";
    }

    .cell-action {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.3rem 0.6rem;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #fff;
      color: var(--accent);
      font-weight: 600;
      font-size: 0.85rem;
      cursor: pointer;
    }

    .cell-action:hover {
      border-color: var(--accent);
      color: var(--accent-hover);
    }

    .detail-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.4);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      z-index: 80;
    }

    .detail-overlay[hidden] {
      display: none;
    }

    .detail-card {
      width: min(900px, 100%);
      max-height: 85vh;
      background: #fff;
      border-radius: 18px;
      border: 1px solid var(--border);
      box-shadow: 0 18px 50px rgba(15, 23, 42, 0.2);
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .detail-card h2 {
      margin: 0;
      font-size: 1.35rem;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.75rem;
      font-size: 0.95rem;
    }

    .detail-block {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.9rem;
      font-size: 0.9rem;
      max-height: 30vh;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .detail-block pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: "SFMono-Regular", "Menlo", "Consolas", "Liberation Mono", monospace;
      font-size: 0.85rem;
    }

    .detail-collapsible summary {
      cursor: pointer;
      font-weight: 600;
      color: var(--accent);
    }

    .detail-actions {
      display: flex;
      justify-content: flex-end;
      gap: 0.6rem;
    }

    .detail-actions button {
      width: auto;
    }

    .section-divider {
      margin: 2rem 0;
      border-top: 1px solid var(--border);
    }

    .key-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 0.85rem;
    }

    .key-grid.add-device-grid {
      grid-template-columns: minmax(140px, 0.6fr) minmax(260px, 1.4fr) minmax(280px, 1.7fr) minmax(280px, 1.7fr);
      align-items: end;
    }

    .key-grid.user-add-grid {
      grid-template-columns: minmax(200px, 0.8fr) minmax(520px, 2fr);
      align-items: end;
    }

    .key-grid.device-grid {
      grid-template-columns: minmax(200px, 1fr) minmax(200px, 1fr) minmax(200px, 1fr) 52px;
      align-items: end;
    }

    .missing-keys-block {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 1rem 1.2rem;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.04);
    }

    .integration-block {
      background: #f8fafc;
      border-color: #e2e8f0;
      opacity: 0.7;
    }

    .integration-block .secondary-button,
    .integration-block button {
      background: #f1f5f9;
      border-color: #e2e8f0;
      color: #94a3b8;
      cursor: not-allowed;
      pointer-events: none;
    }

    .hint-divider {
      margin: 0.6rem 0 0.9rem;
      border-top: 1px dashed #cbd5f5;
    }

    .remove-cell {
      display: flex;
      justify-content: flex-end;
      align-items: flex-start;
      padding-top: 1.55rem;
      padding-bottom: 0;
    }

    .remove-cell .danger-button {
      width: 42px;
      height: 42px;
    }

    @media (max-width: 1100px) {
      .key-grid.user-grid {
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      }

      .key-grid.user-grid .remove-cell {
        justify-content: flex-start;
        padding-bottom: 0;
      }
    }

    @media (max-width: 900px) {
      .key-grid.add-device-grid {
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      }

      .key-grid.user-add-grid {
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      }

      .key-grid.device-grid {
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      }

      .remove-cell {
        justify-content: flex-start;
      }
    }

    .device-rows {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .device-row {
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1rem;
      background: #f8fafc;
    }

    .table-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.6rem;
      margin-top: 0.75rem;
    }

    .table-actions form {
      margin: 0;
    }

    .table-actions.decode-actions {
      margin-bottom: 0.8rem;
    }

    .analyze-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.8rem;
      margin: 0.8rem 0 1.2rem;
    }

    .stat-card {
      padding: 1rem;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: #f8fafc;
    }

    .stat-card h3 {
      margin: 0 0 0.4rem;
      font-size: 0.95rem;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }

    .stat-card .stat-value {
      font-size: 1.5rem;
      font-weight: 700;
      color: #0f172a;
    }

    .analyze-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
    }

    .chart-card {
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1rem;
      background: #fff;
      box-shadow: 0 12px 30px rgba(15, 23, 42, 0.06);
      margin-bottom: 1rem;
    }

    .chart-card summary {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      cursor: pointer;
      font-weight: 700;
      margin-bottom: 0.6rem;
      list-style: none;
    }

    .chart-card summary::-webkit-details-marker {
      display: none;
    }

    .chart-card summary::after {
      content: "▸";
      margin-left: auto;
      transition: transform 0.15s ease;
      opacity: 0.7;
    }

    .chart-card[open] summary::after {
      transform: rotate(90deg);
    }

    .chart-card h3 {
      margin: 0 0 0.6rem;
      font-size: 1.05rem;
    }

    .bar-chart {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }

    .bar-row {
      display: grid;
      grid-template-columns: minmax(70px, 1fr) 4fr minmax(36px, 64px);
      align-items: center;
      gap: 0.6rem;
      font-size: 0.9rem;
    }

    .bar-track {
      height: 10px;
      border-radius: 999px;
      background: #e2e8f0;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border-radius: 999px;
      background: var(--accent);
    }

    .map-panel {
      width: 100%;
      height: 260px;
      min-height: 260px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: #f8fafc;
      position: relative;
      overflow: hidden;
      margin-top: 0.8rem;
    }

    .map-panel.map-expanded {
      position: fixed;
      top: 2.5rem;
      left: 1.5rem;
      right: 1.5rem;
      bottom: 1.5rem;
      width: auto;
      height: auto;
      min-height: 0;
      border-radius: 18px;
      margin-top: 0;
      z-index: 2000;
      background: #e2e8f0;
      box-shadow: 0 24px 60px rgba(15, 23, 42, 0.35);
    }

    .map-panel .map-svg {
      width: 100%;
      height: 100%;
      position: absolute;
      inset: 0;
      pointer-events: none;
    }

    .map-panel iframe {
      width: 100%;
      height: 100%;
      border: 0;
      position: absolute;
      inset: 0;
    }

    .leaflet-container {
      position: relative;
      overflow: hidden;
      outline: 0;
      background: #e2e8f0;
    }

    .leaflet-pane,
    .leaflet-tile,
    .leaflet-marker-icon,
    .leaflet-marker-shadow,
    .leaflet-tile-container,
    .leaflet-pane > svg,
    .leaflet-pane > canvas {
      position: absolute;
      left: 0;
      top: 0;
    }

    .leaflet-pane {
      z-index: 400;
    }

    .leaflet-tile-pane {
      z-index: 200;
    }

    .leaflet-overlay-pane {
      z-index: 400;
    }

    .leaflet-shadow-pane {
      z-index: 500;
    }

    .leaflet-marker-pane {
      z-index: 600;
    }

    .leaflet-tooltip-pane {
      z-index: 650;
    }

    .leaflet-popup-pane {
      z-index: 700;
    }

    .leaflet-tile-container {
      z-index: 200;
    }

    .leaflet-tile {
      width: 256px;
      height: 256px;
    }

    .leaflet-overlay-pane svg {
      overflow: visible;
    }

    .map-toggle-button {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      border: 0;
      background: transparent;
      color: #0f172a;
      font-size: 1rem;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }

    .map-toggle-button:hover {
      background: rgba(37, 99, 235, 0.12);
    }

    .map-toggle-button.is-active {
      background: rgba(37, 99, 235, 0.18);
      color: #1d4ed8;
    }

    .map-toggle-button .material-icons {
      font-size: 20px;
      line-height: 1;
    }

    .map-button-row {
      display: flex;
      gap: 0.6rem;
      padding: 0.25rem 0.35rem;
      border-radius: 12px;
      border: 1px solid rgba(15, 23, 42, 0.2);
      background: rgba(255, 255, 255, 0.95);
      box-shadow: 0 6px 16px rgba(15, 23, 42, 0.18);
      pointer-events: auto;
      z-index: 2;
    }

    .map-panel .leaflet-bottom.leaflet-left {
      left: 50%;
      right: auto;
      transform: translateX(-50%);
    }

    .leaflet-zoom-animated {
      transform-origin: 0 0;
    }

    .leaflet-zoom-hide {
      visibility: hidden;
    }

    .leaflet-control-container {
      position: absolute;
      inset: 0;
      z-index: 1000;
      pointer-events: none;
    }

    .leaflet-top,
    .leaflet-bottom {
      position: absolute;
      z-index: 1000;
      pointer-events: none;
    }

    .leaflet-top {
      top: 0;
    }

    .leaflet-bottom {
      bottom: 0;
    }

    .leaflet-left {
      left: 0;
    }

    .leaflet-right {
      right: 0;
    }

    .leaflet-control {
      margin: 10px;
      pointer-events: auto;
    }

    .leaflet-bar {
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(15, 23, 42, 0.18);
      overflow: hidden;
      background: rgba(255, 255, 255, 0.95);
      border: 1px solid rgba(15, 23, 42, 0.2);
      display: inline-block;
    }

    .map-point {
      fill: #0f172a;
      opacity: 0.8;
    }

    .map-legend {
      position: absolute;
      bottom: 0.7rem;
      right: 0.7rem;
      background: rgba(255, 255, 255, 0.9);
      border-radius: 10px;
      padding: 0.35rem 0.6rem;
      font-size: 0.75rem;
      color: #0f172a;
      border: 1px solid rgba(148, 163, 184, 0.4);
    }

    .table-scroll {
      overflow-x: auto;
    }

    .analytics-controls {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.8rem;
      margin-top: 0.8rem;
    }

    .analytics-controls .full-row {
      grid-column: 1 / -1;
    }

    .analytics-controls .control-row {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }

    .analytics-inline {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .analytics-inline input {
      min-width: 0;
    }

    .analytics-hint {
      font-size: 0.8rem;
      color: var(--text-muted);
    }

    .chart-canvas {
      width: 100%;
      height: calc(100% - 2.75rem);
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #f8fafc;
      display: block;
    }

    .chart-wrapper {
      height: 360px;
      width: 100%;
      margin-top: 0.8rem;
      position: relative;
      background: #fff;
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1rem 1rem 3.75rem;
      box-sizing: border-box;
    }

    .chart-wrapper.chart-expanded {
      position: fixed;
      top: 2.5rem;
      left: 1rem;
      right: 1rem;
      bottom: 1.5rem;
      height: auto;
      width: calc(100% - 2rem);
      z-index: 1900;
      margin-top: 0;
      border-radius: 18px;
      box-shadow: 0 24px 60px rgba(15, 23, 42, 0.35);
    }

    .chart-button-row {
      position: absolute;
      bottom: 0.75rem;
      left: 50%;
      transform: translateX(-50%);
      display: flex;
      gap: 0.6rem;
      z-index: 2;
    }

    .chart-toggle-button {
      position: static;
      width: 36px;
      height: 36px;
      border-radius: 10px;
      border: 1px solid rgba(15, 23, 42, 0.2);
      background: rgba(255, 255, 255, 0.95);
      color: #0f172a;
      font-size: 1rem;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 6px 16px rgba(15, 23, 42, 0.18);
    }

    .chart-toggle-button.is-active {
      background: rgba(37, 99, 235, 0.18);
      color: #1d4ed8;
    }

    .chart-toggle-button:hover {
      background: #ffffff;
    }

    .chart-toggle-button .material-icons {
      font-size: 20px;
      line-height: 1;
    }

    #stats_panel {
      margin: 0.6rem 0 0.8rem;
    }

    .stats-card summary {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      cursor: pointer;
      font-weight: 600;
      list-style: none;
    }

    .stats-card summary::-webkit-details-marker {
      display: none;
    }

    .stats-card summary::after {
      content: "▸";
      margin-left: auto;
      transition: transform 0.15s ease;
      opacity: 0.7;
    }

    .stats-card[open] summary::after {
      transform: rotate(90deg);
    }

    #stats_box {
      margin-top: 0.4rem;
    }

    .stats-table {
      border-collapse: collapse;
      width: 100%;
      max-width: 520px;
      font-size: 0.9rem;
    }

    .stats-table td {
      padding: 0.35rem 0.5rem;
      border-bottom: 1px solid #e2e8f0;
    }

    .analysis-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }

    .analysis-table th,
    .analysis-table td {
      padding: 0.4rem 0.5rem;
      border-bottom: 1px solid #e2e8f0;
      text-align: left;
    }

    .analysis-table-wrapper {
      max-height: 360px;
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fff;
    }

    .map-controls {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 0.8rem;
      margin-top: 0.6rem;
    }

    .map-controls .control-row {
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }

    .map-controls .full-row {
      grid-column: 1 / -1;
    }

    .map-svg {
      width: 100%;
      height: 100%;
    }

    .tag {
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      background: rgba(37, 99, 235, 0.12);
      color: var(--accent);
      border: 1px solid rgba(37, 99, 235, 0.2);
      margin-left: 0.4rem;
    }

    .brand-note {
      font-size: 0.95rem;
      color: #475569;
      text-align: center;
      line-height: 1.4;
    }

    .brand-note a {
      color: var(--accent);
      font-weight: 600;
      text-decoration: none;
    }

    .brand-note a:hover {
      text-decoration: underline;
    }

    .progress-bar {
      width: 220px;
      height: 10px;
      border-radius: 999px;
      background: #e2e8f0;
      overflow: hidden;
      position: relative;
    }

    .progress-bar::after {
      content: "";
      position: absolute;
      inset: 0;
      width: 40%;
      background: linear-gradient(90deg, rgba(37, 99, 235, 0.2), rgba(37, 99, 235, 0.9), rgba(37, 99, 235, 0.2));
      animation: progress-slide 1.1s ease-in-out infinite;
    }

    @keyframes progress-slide {
      0% { transform: translateX(-60%); }
      100% { transform: translateX(160%); }
    }

    .progress-track {
      width: 100%;
      height: 10px;
      border-radius: 999px;
      background: #e2e8f0;
      overflow: hidden;
      margin-top: 0.5rem;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #1d4ed8, #3b82f6);
      width: 0%;
      transition: width 0.2s ease-out;
    }

    .progress-meta {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.9rem;
      color: #475569;
      margin-top: 0.5rem;
      gap: 1rem;
      flex-wrap: wrap;
    }
  </style>
"""

SCRIPT_BLOCK = """
  <script>
    function randomHex(byteLength) {
      const array = new Uint8Array(byteLength);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(array);
      } else {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * 256);
        }
      }
      return Array.from(array, (byte) =>
        byte.toString(16).padStart(2, "0")
      ).join("").toUpperCase();
    }

    function generateField(fieldId, type) {
      let value = "";
      switch (type) {
        case "gateway_eui":
          value = randomHex(8);
          break;
        case "devaddr":
          value = randomHex(4);
          break;
        case "skey":
          value = randomHex(16);
          break;
        default:
          return;
      }
      const input = document.getElementById(fieldId);
      if (input) {
        input.value = value;
      }
    }

    function generatePassword(length = 16) {
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
      const array = new Uint8Array(length);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(array);
      } else {
        for (let i = 0; i < array.length; i++) {
          array[i] = Math.floor(Math.random() * chars.length);
        }
      }
      let out = "";
      for (let i = 0; i < array.length; i++) {
        out += chars[array[i] % chars.length];
      }
      return out;
    }
    function copyField(fieldId) {
      const input = document.getElementById(fieldId);
      if (!input) return;
      input.select();
      input.setSelectionRange(0, 99999);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(input.value || "");
    } else {
      document.execCommand("copy");
    }
    }

    function initSortableTable(section) {
      if (!section) return;
      const table = section.querySelector("[data-sortable-table]");
      if (!table) return;
      const tbody = table.querySelector("tbody");
      const originalRows = Array.from(tbody.rows);
      const rowData = originalRows.map((row) => {
        const data = {};
        Object.keys(row.dataset || {}).forEach((key) => {
          data[key] = (row.dataset[key] || "").toLowerCase();
        });
        return { element: row.cloneNode(true), data };
      });

      const numericColumns = new Set(
        (table.dataset.numericKeys || "").split(",").filter(Boolean)
      );
      let sortKey = table.dataset.defaultSortKey || null;
      let sortDir = 1;

      const limitSelect = section.querySelector("[data-table-limit]");

      function apply() {
        let rows = rowData.slice();

        if (sortKey) {
          rows = rows.sort((a, b) => {
            const aVal = a.data[sortKey] || "";
            const bVal = b.data[sortKey] || "";
            if (numericColumns.has(sortKey)) {
              const aNum = parseFloat(aVal) || 0;
              const bNum = parseFloat(bVal) || 0;
              return sortDir * (aNum - bNum);
            }
            return (
              sortDir *
              aVal.localeCompare(bVal, undefined, { sensitivity: "base" })
            );
          });
        }

        let limit = rows.length;
        if (limitSelect && limitSelect.value !== "all") {
          const parsed = parseInt(limitSelect.value, 10);
          if (!isNaN(parsed)) {
            limit = parsed;
          }
        }

        const fragment = document.createDocumentFragment();
        rows.slice(0, limit).forEach((row) => {
          fragment.appendChild(row.element.cloneNode(true));
        });
        tbody.innerHTML = "";
        tbody.appendChild(fragment);
      }

      section.querySelectorAll("[data-sort-key]").forEach((button) => {
        button.addEventListener("click", () => {
          const key = button.dataset.sortKey;
          if (sortKey === key) {
            sortDir *= -1;
          } else {
            sortKey = key;
            sortDir = 1;
          }
          section
            .querySelectorAll("[data-sort-key]")
            .forEach((btn) => btn.classList.remove("sorted-asc", "sorted-desc"));
          button.classList.add(sortDir === 1 ? "sorted-asc" : "sorted-desc");
          apply();
        });
      });

      if (limitSelect) {
        limitSelect.addEventListener("change", apply);
      }

      apply();
    }

    function initTruncation(section) {
      if (!section) return;
      section.querySelectorAll("[data-truncate]").forEach((cell) => {
        const full = cell.dataset.full || "";
        if (!full || full.length <= 80) {
          cell.textContent = full;
          return;
        }
        const preview = full.slice(0, 80) + "…";
        cell.textContent = preview;
        cell.classList.add("truncate-cell");
        cell.addEventListener("click", () => {
          const isExpanded = cell.classList.toggle("expanded");
          cell.textContent = isExpanded ? full : preview;
        });
      });
    }

    function initDetailOverlay(section) {
      if (!section) return;
      const overlay = document.querySelector("[data-detail-overlay]");
      if (!overlay) return;
      const title = overlay.querySelector("[data-detail-title]");
      const meta = overlay.querySelector("[data-detail-meta]");
      const payload = overlay.querySelector("[data-detail-payload]");
      const decoded = overlay.querySelector("[data-detail-decoded]");
      const closeBtn = overlay.querySelector("[data-detail-close]");

      const close = () => {
        overlay.hidden = true;
      };
      closeBtn?.addEventListener("click", close);
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) {
          close();
        }
      });

      section.addEventListener("click", (event) => {
        const btn = event.target.closest("[data-detail-trigger]");
        if (!btn) return;
        const row = btn.closest("tr");
        if (!row) return;
        title.textContent = `Packet #${row.dataset.index || "?"}`;
        meta.innerHTML = `
          <div><strong>Status:</strong> ${row.dataset.status || "-"}</div>
          <div><strong>DevAddr:</strong> ${row.dataset.devaddr || "-"}</div>
          <div><strong>FCnt:</strong> ${row.dataset.fcnt || "-"}</div>
          <div><strong>FPort:</strong> ${row.dataset.fport || "-"}</div>
          <div><strong>Time parsed:</strong> ${row.dataset.time || "-"}</div>
          <div><strong>Timestamp:</strong> ${row.dataset.timeUnix || "-"}</div>
          <div><strong>Time (UTC):</strong> ${row.dataset.timeUtc || "-"}</div>
        `;
        payload.textContent = row.dataset.payload || "";
        const decodedRaw = row.dataset.decoded || "";
        let formatted = decodedRaw;
        try {
          const parsed = JSON.parse(decodedRaw);
          formatted = JSON.stringify(parsed, null, 2);
        } catch (_) {
          formatted = decodedRaw;
        }
        decoded.textContent = formatted || "";
        overlay.hidden = false;
      });
    }

    function initFileList() {
      const list = document.querySelector("[data-file-list]");
      if (!list) return;
      const items = Array.from(list.querySelectorAll("[data-file-item]"));
      const searchInput = document.querySelector("[data-file-search]");
      const sortSelect = document.querySelector("[data-file-sort]");
      let emptyState = list.querySelector("[data-file-empty]");

      const parseDate = (value) => {
        if (!value) return 0;
        const cleaned = value.replace(" UTC", "Z").replace(" ", "T");
        const parsed = Date.parse(cleaned);
        return Number.isFinite(parsed) ? parsed : 0;
      };

      const getName = (item) => (item.dataset.fileName || "").toLowerCase();
      const getDate = (item) => parseDate(item.dataset.fileDate || "");

      const applyList = () => {
        const term = (searchInput?.value || "").toLowerCase().trim();
        const sortValue = sortSelect?.value || "date_desc";
        let filtered = items.filter((item) => {
          if (!term) return true;
          return getName(item).includes(term);
        });

        filtered = filtered.sort((a, b) => {
          if (sortValue === "name_asc") {
            return getName(a).localeCompare(getName(b));
          }
          if (sortValue === "name_desc") {
            return getName(b).localeCompare(getName(a));
          }
          if (sortValue === "date_asc") {
            return getDate(a) - getDate(b);
          }
          return getDate(b) - getDate(a);
        });

        const fragment = document.createDocumentFragment();
        filtered.forEach((item) => fragment.appendChild(item));
        list.innerHTML = "";
        list.appendChild(fragment);

        if (!filtered.length) {
          if (!emptyState) {
            emptyState = document.createElement("div");
            emptyState.className = "hint";
            emptyState.dataset.fileEmpty = "true";
            emptyState.textContent = "No matching files.";
          }
          list.appendChild(emptyState);
        }
      };

      searchInput?.addEventListener("input", applyList);
      sortSelect?.addEventListener("change", applyList);
      applyList();
    }

    function formatTimeParts(value, length) {
      return String(value).padStart(length, "0");
    }

    function formatSendTime(msValue) {
      if (msValue === undefined || msValue === null || msValue === "") {
        return "-";
      }
      const msNumber = Number(msValue);
      if (!Number.isFinite(msNumber)) {
        return "-";
      }
      const date = new Date(msNumber);
      if (Number.isNaN(date.getTime())) {
        return "-";
      }
      return (
        `${formatTimeParts(date.getHours(), 2)}:` +
        `${formatTimeParts(date.getMinutes(), 2)}:` +
        `${formatTimeParts(date.getSeconds(), 2)}.` +
        `${formatTimeParts(date.getMilliseconds(), 3)}`
      );
    }

    function formatReplaySendTimes(section) {
      if (!section) return;
      section.querySelectorAll("tr[data-send-time-ms]").forEach((row) => {
        const cell = row.querySelector(".send-time-cell");
        if (!cell) return;
        cell.textContent = formatSendTime(row.dataset.sendTimeMs || "");
      });
    }

    function initReplayStream() {
      const container = document.querySelector("[data-replay-stream]");
      if (!container) return;
      const token = container.dataset.replayToken || "";
      const statusUrl = container.dataset.replayStatusUrl || "";
      if (!token || !statusUrl) return;

      const statusBlock = container.querySelector("[data-replay-status]");
      const progressFill = container.querySelector("[data-replay-progress]");
      const progressText = container.querySelector("[data-replay-progress-text]");
      const metaTarget = container.querySelector("[data-replay-target]");
      const etaText = container.querySelector("[data-replay-eta]");
      const logBody = document.querySelector("[data-replay-log-body]");
      const stopButton = document.querySelector("[data-stop-replay]");
      const resumeButton = document.querySelector("[data-resume-replay]");
      const restartButton = document.querySelector("[data-restart-replay]");
      let etaTimer = null;

      let received = 0;
      let done = false;

      const formatDuration = (ms) => {
        const totalSeconds = Math.max(0, Math.ceil(ms / 1000));
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        if (hours > 0) {
          return `${hours}:${formatTimeParts(minutes, 2)}:${formatTimeParts(seconds, 2)}`;
        }
        return `${minutes}:${formatTimeParts(seconds, 2)}`;
      };

      const updateEta = (data) => {
        if (!etaText) return;
        if (etaTimer) {
          clearInterval(etaTimer);
          etaTimer = null;
        }
        if (data.status !== "running") {
          etaText.textContent = "ETA 0:00";
          return;
        }
        const delayMs = Number(data.delay_ms) || 0;
        const total = data.total || 0;
        const processed = (data.sent || 0) + (data.errors || 0);
        const remaining = Math.max(0, total - processed);
        if (!delayMs || remaining === 0) {
          etaText.textContent = "ETA 0:00";
          return;
        }
        const targetTime = Date.now() + remaining * delayMs;
        const render = () => {
          const remainingMs = targetTime - Date.now();
          etaText.textContent = `ETA ${formatDuration(remainingMs)}`;
        };
        render();
        etaTimer = window.setInterval(render, 250);
      };

      const updateStatus = (data) => {
        const total = data.total || 0;
        const sent = data.sent || 0;
        const errors = data.errors || 0;
        const processed = sent + errors;
        const percent = total ? Math.min(100, Math.round((processed / total) * 100)) : 0;

        if (progressFill) {
          progressFill.style.width = `${percent}%`;
        }
        if (progressText) {
          progressText.textContent = `Sent ${sent} of ${total} · Errors ${errors}`;
        }
        if (metaTarget) {
          metaTarget.textContent = `Target ${data.host || "?"}:${data.port || "?"} · Delay ${data.delay_ms || 0} ms`;
        }
        if (statusBlock) {
          statusBlock.classList.remove("info", "success", "error");
          if (data.status === "done") {
            statusBlock.classList.add(errors === 0 ? "success" : "error");
            statusBlock.textContent = `Replay done. Sent ${sent}, errors ${errors}.`;
          } else if (data.status === "stopped") {
            statusBlock.classList.add("error");
            statusBlock.textContent = `Replay stopped. Sent ${sent}, errors ${errors}.`;
          } else {
            statusBlock.classList.add("info");
            statusBlock.textContent = `Replaying... Sent ${sent} of ${total}.`;
          }
        }

        if (stopButton) {
          const isRunning = data.status === "running";
          stopButton.disabled = !isRunning;
          stopButton.classList.toggle("is-hidden", !isRunning);
        }
        if (resumeButton) {
          const isStopped = data.status === "stopped";
          resumeButton.disabled = !isStopped;
          resumeButton.classList.toggle("is-hidden", !isStopped);
        }
        if (restartButton) {
          const showRestart = data.status === "stopped" || data.status === "done";
          restartButton.disabled = !showRestart;
          restartButton.classList.toggle("is-hidden", !showRestart);
        }
        updateEta(data);
      };

      const appendLines = (lines) => {
        if (!logBody || !Array.isArray(lines) || lines.length === 0) return;
        const fragment = document.createDocumentFragment();
        lines.forEach((line) => {
          const row = document.createElement("tr");
          row.className = line.css || "";
          row.dataset.index = line.index ?? "";
          row.dataset.status = line.status ?? "";
          row.dataset.sendTimeMs = line.send_time_ms ?? "";
          row.dataset.gateway = line.gateway ?? "";
          row.dataset.fcnt = line.fcnt ?? "";
          row.dataset.freq = line.freq ?? "";
          row.dataset.size = line.size ?? "";
          row.dataset.message = line.message ?? "";

          const cells = [
            { value: line.index },
            { value: line.status },
            { value: formatSendTime(line.send_time_ms), className: "send-time-cell" },
            { value: line.gateway },
            { value: line.fcnt },
            { value: line.freq },
            { value: line.size },
            { value: line.message },
          ];
          cells.forEach((cellData) => {
            const cell = document.createElement("td");
            if (cellData.className) {
              cell.className = cellData.className;
            }
            const value = cellData.value;
            cell.textContent = value === undefined || value === null || value === "" ? "-" : value;
            row.appendChild(cell);
          });
          fragment.appendChild(row);
        });
        logBody.appendChild(fragment);
      };

      const poll = () => {
        if (done) return;
        const url = new URL(statusUrl, window.location.origin);
        url.searchParams.set("token", token);
        url.searchParams.set("since", String(received));
        fetch(url.toString(), { cache: "no-store" })
          .then((response) => {
            if (!response.ok) {
              throw new Error("Replay status request failed.");
            }
            return response.json();
          })
          .then((data) => {
            if (data.error) {
              throw new Error(data.error);
            }
            if (Array.isArray(data.lines)) {
              appendLines(data.lines);
            }
            if (typeof data.count === "number") {
              received = data.count;
            }
            updateStatus(data);
            if (data.status === "done" || data.status === "stopped") {
              done = true;
              return;
            }
            window.setTimeout(poll, 600);
          })
          .catch(() => {
            if (!done) {
              window.setTimeout(poll, 1200);
            }
          });
      };

      poll();
    }

    document.addEventListener("DOMContentLoaded", () => {
      const logSection = document.querySelector("[data-log-section]");
      formatReplaySendTimes(logSection);
      if (logSection && !logSection.dataset.liveReplay) {
        initSortableTable(logSection);
        initTruncation(logSection);
      }
      initSortableTable(document.querySelector("[data-decode-section]"));
      initTruncation(document.querySelector("[data-decode-section]"));
      initDetailOverlay(document.querySelector("[data-decode-section]"));
      initFileList();
      initReplayStream();
      document.querySelectorAll("[data-toggle-visibility]").forEach((button) => {
        button.addEventListener("click", () => {
          const targetId = button.dataset.toggleVisibility;
          const input = document.getElementById(targetId);
          if (!input) return;
          const isHidden = input.type === "password";
          input.type = isHidden ? "text" : "password";
          button.setAttribute("aria-pressed", isHidden ? "true" : "false");
          button.title = isHidden ? "Hide key" : "Show key";
        });
      });
      const drop = document.querySelector("[data-file-drop]");
      const form = drop?.closest("form");
      const overlay = document.querySelector("[data-loading-overlay]");
      const input = document.getElementById("logfile");
      const selected = document.querySelector("[data-file-selected]");
      const payloadSelect = document.querySelector("[data-payload-example]");
      const payloadInput = document.getElementById("app_payload_hex");
      const fportInput = document.getElementById("fport");

      if (payloadSelect && payloadInput && fportInput) {
        payloadSelect.addEventListener("change", () => {
          const opt = payloadSelect.selectedOptions[0];
          const payload = opt?.value;
          const port = opt?.dataset.port;
          if (payload) {
            payloadInput.value = payload;
          }
          if (port) {
            fportInput.value = port;
          }
        });
      }

      if (drop && input && selected) {
        const updateLabel = () => {
          if (input.files && input.files.length > 0) {
            selected.textContent = input.files.length === 1 ? input.files[0].name : `${input.files.length} files selected`;
          }
        };
        const autoScan = () => {
          if (!input.files || input.files.length === 0) {
            return;
          }
          const scanUrl = form?.dataset.scanUrl;
          if (form && scanUrl) {
            form.action = scanUrl;
            form.submit();
          }
        };

        drop.addEventListener("click", () => input.click());

        ["dragenter", "dragover"].forEach((evt) =>
          drop.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            drop.classList.add("dragover");
          })
        );
        ["dragleave", "drop"].forEach((evt) =>
          drop.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (evt === "drop" && e.dataTransfer?.files?.length) {
              const dt = new DataTransfer();
              Array.from(e.dataTransfer.files).forEach((file) => dt.items.add(file));
              input.files = dt.files;
              updateLabel();
              autoScan();
            }
            drop.classList.remove("dragover");
          })
        );

        input.addEventListener("change", () => {
          updateLabel();
          autoScan();
        });
        updateLabel();
      }

      if (overlay) {
        document.querySelectorAll("form").forEach((formEl) => {
          formEl.addEventListener("submit", (event) => {
            const submitter = event.submitter;
            if (submitter && submitter.dataset.showLoader === "true") {
              overlay.hidden = false;
            }
          });
        });
      }

      const decodeOverlay = document.querySelector("[data-decode-overlay]");
      if (decodeOverlay) {
        const progressUrl = decodeOverlay.dataset.decodeProgressUrl || "";
        const progressFill = decodeOverlay.querySelector("[data-decode-progress]");
        const progressText = decodeOverlay.querySelector("[data-decode-progress-text]");
        const progressPercent = decodeOverlay.querySelector("[data-decode-progress-percent]");
        const makeProgressId = () => {
          if (window.crypto?.randomUUID) return window.crypto.randomUUID();
          return `p_${Date.now()}_${Math.random().toString(16).slice(2)}`;
        };
        let decodePollTimer = null;
        const stopDecodePoll = () => {
          if (decodePollTimer) {
            clearInterval(decodePollTimer);
            decodePollTimer = null;
          }
        };
        const startDecodePoll = (progressId) => {
          if (!progressUrl || !progressId) return;
          const poll = async () => {
            try {
              const response = await fetch(`${progressUrl}?progress_id=${encodeURIComponent(progressId)}`, {
                credentials: "same-origin",
                cache: "no-store"
              });
              if (!response.ok) return;
              const data = await response.json();
              const total = Number(data.total) || 0;
              const completed = Number(data.completed) || 0;
              const percent = total ? Math.min(100, Math.max(0, Math.round((completed / total) * 100))) : 0;
              if (progressFill) {
                const hue = Math.max(140, 215 - Math.round(percent * 0.6));
                progressFill.style.width = `${percent}%`;
                progressFill.style.background = `linear-gradient(90deg, hsl(${hue}, 85%, 45%), hsl(${hue + 15}, 85%, 55%))`;
              }
              if (progressPercent) progressPercent.textContent = `${percent}%`;
              if (progressText) {
                progressText.textContent = total
                  ? `Decoding ${completed} of ${total}`
                  : "Decoding…";
              }
            } catch (err) {
              stopDecodePoll();
            }
          };
          stopDecodePoll();
          decodePollTimer = window.setInterval(poll, 500);
          poll();
        };
        document.querySelectorAll("form").forEach((formEl) => {
          formEl.addEventListener("submit", (event) => {
            const submitter = event.submitter;
            if (submitter && submitter.dataset.showDecodeLoader === "true") {
              event.preventDefault();
              const progressId = makeProgressId();
              const progressInput = formEl.querySelector("[data-decode-progress-id]");
              if (progressInput) progressInput.value = progressId;
              if (progressFill) progressFill.style.width = "0%";
              if (progressText) progressText.textContent = "Decoding…";
              if (progressPercent) progressPercent.textContent = "0%";
              decodeOverlay.hidden = false;
              startDecodePoll(progressId);
              const actionUrl = formEl.getAttribute("action") || window.location.href;
              fetch(actionUrl, {
                method: formEl.method || "POST",
                body: new FormData(formEl),
                credentials: "same-origin"
              }).then((response) => response.text())
                .then((html) => {
                  stopDecodePoll();
                  document.open();
                  document.write(html);
                  document.close();
                })
                .catch(() => {
                  stopDecodePoll();
                  if (progressText) progressText.textContent = "Decode failed. Please retry.";
                });
            }
          });
        });
      }

      const scanOverlay = document.querySelector("[data-scan-overlay]");
      if (scanOverlay) {
        const closeBtn = scanOverlay.querySelector("[data-scan-close]");
        const close = () => {
          scanOverlay.hidden = true;
        };
        closeBtn?.addEventListener("click", close);
        scanOverlay.addEventListener("click", (event) => {
          if (event.target === scanOverlay) {
            close();
          }
        });
      }

      const generatedOverlay = document.querySelector("[data-generated-overlay]");
      if (generatedOverlay) {
        const downloadUrl = generatedOverlay.dataset.generatedDownloadUrl || "";
        const downloadName = generatedOverlay.dataset.generatedFilename || "";
        if (downloadUrl) {
          const directLink = document.createElement("a");
          directLink.href = downloadUrl;
          if (downloadName) {
            directLink.download = downloadName;
          }
          directLink.click();
        }
        const closeBtn = generatedOverlay.querySelector("[data-generated-close]");
        const close = () => {
          generatedOverlay.hidden = true;
        };
        closeBtn?.addEventListener("click", close);
        generatedOverlay.addEventListener("click", (event) => {
          if (event.target === generatedOverlay) {
            close();
          }
        });
      }

      const passwordModal = document.querySelector("[data-password-modal]");
      if (passwordModal) {
        const openButtons = document.querySelectorAll("[data-password-reset]");
        const closeBtn = passwordModal.querySelector("[data-password-close]");
        const usernameField = passwordModal.querySelector("[data-password-username]");
        const userLabel = passwordModal.querySelector("[data-password-user]");
        const passwordInput = passwordModal.querySelector("[data-password-input]");
        const generateBtn = passwordModal.querySelector("[data-password-generate]");
        const copyBtn = passwordModal.querySelector("[data-password-copy]");

        const open = (username) => {
          if (usernameField) usernameField.value = username;
          if (userLabel) userLabel.textContent = username;
          if (passwordInput) passwordInput.value = "";
          passwordModal.hidden = false;
        };

        const close = () => {
          passwordModal.hidden = true;
        };

        openButtons.forEach((button) => {
          button.addEventListener("click", () => {
            const username = button.dataset.passwordReset || "";
            if (!username) return;
            open(username);
          });
        });

        generateBtn?.addEventListener("click", () => {
          if (!passwordInput) return;
          passwordInput.value = generatePassword(16);
        });

        copyBtn?.addEventListener("click", () => {
          if (!passwordInput) return;
          passwordInput.select();
          passwordInput.setSelectionRange(0, 99999);
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(passwordInput.value || "");
          } else {
            document.execCommand("copy");
          }
        });

        closeBtn?.addEventListener("click", close);
        passwordModal.addEventListener("click", (event) => {
          if (event.target === passwordModal) {
            close();
          }
        });
      }

      document.querySelectorAll(".field-controls").forEach((controls) => {
        if (passwordModal && passwordModal.contains(controls)) {
          return;
        }
        const input = controls.querySelector("[data-password-input]");
        if (!input) return;
        const generateBtn = controls.querySelector("[data-password-generate]");
        const copyBtn = controls.querySelector("[data-password-copy]");
        generateBtn?.addEventListener("click", () => {
          input.value = generatePassword(16);
        });
        copyBtn?.addEventListener("click", () => {
          input.select();
          input.setSelectionRange(0, 99999);
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(input.value || "");
          } else {
            document.execCommand("copy");
          }
        });
      });

      document.querySelectorAll("[data-user-name]").forEach((el) => {
        const name = el.dataset.userName || "";
        let hash = 0;
        for (let i = 0; i < name.length; i++) {
          hash = ((hash << 5) - hash) + name.charCodeAt(i);
          hash |= 0;
        }
        const hue = Math.abs(hash) % 360;
        el.style.color = `hsl(${hue}, 68%, 36%)`;
      });

      const tempPasswordInput = document.querySelector("[data-temp-password]");
      const tempGenerateBtn = document.querySelector("[data-temp-generate]");
      const tempCopyBtn = document.querySelector("[data-temp-copy]");
      if (tempPasswordInput && tempGenerateBtn) {
        tempGenerateBtn.addEventListener("click", () => {
          tempPasswordInput.value = generatePassword(16);
        });
      }
      if (tempPasswordInput && tempCopyBtn) {
        tempCopyBtn.addEventListener("click", () => {
          tempPasswordInput.select();
          tempPasswordInput.setSelectionRange(0, 99999);
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(tempPasswordInput.value || "");
          } else {
            document.execCommand("copy");
          }
        });
      }

      const deleteForm = document.querySelector("[data-delete-form]");
      if (deleteForm) {
        const deleteInput = deleteForm.querySelector("[data-delete-input]");
        document.querySelectorAll("[data-delete-devaddr]").forEach((button) => {
          button.addEventListener("click", () => {
            const devaddr = button.dataset.deleteDevaddr || "";
            if (!devaddr) return;
            if (!confirm(`Remove device ${devaddr}?`)) {
              return;
            }
            if (deleteInput) {
              deleteInput.value = devaddr;
            }
            deleteForm.submit();
          });
        });
      }

      const decoderDeleteForm = document.querySelector("[data-decoder-delete-form]");
      if (decoderDeleteForm) {
        const decoderInput = decoderDeleteForm.querySelector("[data-decoder-delete-input]");
        document.querySelectorAll("[data-delete-decoder]").forEach((button) => {
          button.addEventListener("click", () => {
            const decoderId = button.dataset.deleteDecoder || "";
            if (!decoderId) return;
            if (!confirm("Remove this decoder?")) {
              return;
            }
            if (decoderInput) {
              decoderInput.value = decoderId;
            }
            decoderDeleteForm.submit();
          });
        });
      }

      const fileDeleteForm = document.querySelector("[data-file-delete-form]");
      if (fileDeleteForm) {
        const fileInput = fileDeleteForm.querySelector("[data-file-delete-input]");
        document.querySelectorAll("[data-delete-file]").forEach((button) => {
          button.addEventListener("click", () => {
            const fileId = button.dataset.deleteFile || "";
            if (!fileId) return;
            if (!confirm("Remove this log file?")) {
              return;
            }
            if (fileInput) {
              fileInput.value = fileId;
            }
            fileDeleteForm.submit();
          });
        });
      }

      const menuToggle = document.querySelector("[data-menu-toggle]");
      const menuPanel = document.querySelector("[data-menu-panel]");
      if (menuToggle && menuPanel) {
        const closeMenu = () => {
          menuPanel.hidden = true;
          menuToggle.classList.remove("open");
          menuToggle.setAttribute("aria-expanded", "false");
        };
        const openMenu = () => {
          menuPanel.hidden = false;
          menuToggle.classList.add("open");
          menuToggle.setAttribute("aria-expanded", "true");
        };
        menuToggle.addEventListener("click", () => {
          if (menuPanel.hidden) {
            openMenu();
          } else {
            closeMenu();
          }
        });
        menuPanel.querySelectorAll("a").forEach((link) => {
          link.addEventListener("click", () => closeMenu());
        });
        document.addEventListener("click", (event) => {
          if (menuPanel.hidden) return;
          if (menuPanel.contains(event.target) || menuToggle.contains(event.target)) {
            return;
          }
          closeMenu();
        });
      }
    });
  </script>
"""

NAV_HTML = """
  <header class="top-bar">
    <div class="brand">
      <img src="{{ logo_url }}" alt="Smart Parks logo">
      <div>
        <div class="brand-title">OpenCollar LP0 Replay tool</div>
        <div class="brand-subtitle">Smart Parks</div>
      </div>
    </div>
    <div class="top-actions">
      {% if current_user.is_authenticated %}
      <span class="user-pill">Signed in as {{ current_user.id }}</span>
      <form method="POST" action="{{ logout_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit" class="secondary-button icon-only" title="Log out" aria-label="Log out"><span class="material-icons" aria-hidden="true">logout</span></button>
      </form>
      {% endif %}
      {% if show_menu %}
      <button type="button" class="menu-toggle" data-menu-toggle aria-expanded="false" aria-controls="site-menu">
        <span class="material-icons" aria-hidden="true">menu</span>
        <span class="menu-label" aria-hidden="true">Menu</span>
      </button>
      {% endif %}
    </div>
  </header>
  {% if show_menu %}
  <nav id="site-menu" class="menu-panel" data-menu-panel hidden>
    <a class="menu-link {% if active_page == 'start' %}active{% endif %}" href="{{ start_url }}"><span class="material-icons" aria-hidden="true">home</span>Start</a>
    <a class="menu-link {% if active_page == 'devices' %}active{% endif %}" href="{{ devices_url }}"><span class="material-icons" aria-hidden="true">memory</span>Devices</a>
    <a class="menu-link {% if active_page == 'users' %}active{% endif %}" href="{{ users_url }}"><span class="material-icons" aria-hidden="true">group</span>Users</a>
    <a class="menu-link {% if active_page == 'files' %}active{% endif %}" href="{{ files_url }}"><span class="material-icons" aria-hidden="true">folder</span>Files</a>
    <a class="menu-link {% if active_page == 'decoders' %}active{% endif %}" href="{{ decoders_url }}"><span class="material-icons" aria-hidden="true">code</span>Decoders</a>
    <a class="menu-link {% if active_page == 'integrations' %}active{% endif %}" href="{{ integrations_url }}"><span class="material-icons" aria-hidden="true">hub</span>Integrations</a>
    <a class="menu-link {% if active_page == 'about' %}active{% endif %}" href="{{ about_url }}"><span class="material-icons" aria-hidden="true">info</span>About</a>
  </nav>
  {% endif %}
"""

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>OpenCollar LP0 Replay tool</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <h1 class="page-title"><span class="material-icons" aria-hidden="true">home</span>Start</h1>
      <p class="subtitle">Upload a log file or pick a stored log file to scan and continue.</p>

      <form method="POST" action="{{ scan_url }}" enctype="multipart/form-data" data-scan-url="{{ scan_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div>
          <div class="logfile-options">
            <div class="logfile-option">
              <h3>Upload a log file</h3>
              <input id="logfile" type="file" name="logfile" style="display: none;" aria-hidden="true">
              <div class="file-drop" data-file-drop>
                <div class="file-text">
                  <strong>Click to choose or drag & drop</strong>
                  <div class="file-selected" data-file-selected>{{ selected_filename or "No file selected" }}</div>
                  <div class="hint">Upload a JSON Lines file you captured earlier.</div>
                </div>
              </div>
            </div>
            <div class="logfile-option">
              <h3>Stored log file</h3>
              <div class="hint">Pick a previously uploaded log file.</div>
              <select id="stored_log_id" name="stored_log_id">
                <option value="">Select a stored logfile...</option>
                {% for log in stored_logs %}
                <option value="{{ log.id }}" {% if log.id == selected_stored_id %}selected{% endif %}>{{ log.filename }} ({{ log.uploaded_at }})</option>
                {% endfor %}
              </select>
            </div>
          </div>
        </div>

        <div class="form-actions">
          <button type="submit" class="primary-button"><span class="material-icons" aria-hidden="true">search</span>Scan logfile</button>
        </div>

        {% if result_lines %}
        <div class="result {{ result_class }}">
          {% for line in result_lines %}
          <div>{{ line }}</div>
          {% endfor %}
        </div>
        {% endif %}
      </form>

      {% if scan_token %}
      <div class="next-steps">
        <h2>Next steps</h2>
        <div class="action-grid">
          <a class="primary-button" href="{{ decode_url }}?scan_token={{ scan_token }}"><span class="material-icons" aria-hidden="true">lock_open</span>Decrypt &amp; decode</a>
          <a class="secondary-button" href="{{ replay_page_url }}?scan_token={{ scan_token }}"><span class="material-icons" aria-hidden="true">play_arrow</span>Replay</a>
        </div>
      </div>
      {% endif %}
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>

  </div>
  {{ script_block|safe }}
</body>
</html>
"""

REPLAY_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Replay LoRaWAN Log</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1 class="page-title"><span class="material-icons" aria-hidden="true">play_arrow</span>Replay</h1>
          <p class="subtitle">Replay uplinks from <strong>{{ selected_filename }}</strong> to your UDP forwarder.</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back</a>
      </div>

      {% if summary_lines %}
      <div class="result {{ summary_class }}">
        {% for line in summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      {% if result_lines %}
      <div class="result {{ result_class }}">
        {% for line in result_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      <div class="section-divider"></div>

      <form method="POST" action="{{ replay_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div>
          <label for="host">LoRaWAN server host</label>
          <input id="host" name="host" type="text" value="{{ form_values.host }}" {% if replay_token and replay_status == "running" %}disabled{% endif %}>
        </div>
        <div>
          <label for="port">UDP port</label>
          <input id="port" name="port" type="number" value="{{ form_values.port }}" {% if replay_token and replay_status == "running" %}disabled{% endif %}>
          <div class="hint">The default Semtech UDP port is 1700.</div>
        </div>
        <div>
          <label for="delay_ms">Delay between packets (ms)</label>
          <input id="delay_ms" name="delay_ms" type="number" min="0" step="1" value="{{ form_values.delay_ms }}" {% if replay_token and replay_status == "running" %}disabled{% endif %}>
          <div class="hint">Default is 500 milliseconds.</div>
        </div>
        <div>
          <label class="checkbox-row">
            <input id="override_rxpk" name="override_rxpk" type="checkbox" value="1"
                   {% if form_values.override_rxpk %}checked{% endif %}
                   {% if replay_token and replay_status == "running" %}disabled{% endif %}>
            Override rxpk values for server compatibility
          </label>
          <div class="hint">Uses freq=868.1, chan=0, rfch=0, stat=1, modu=LORA, datr=SF9BW125, codr=4/5.</div>
        </div>
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        {% if replay_token %}
        <input type="hidden" name="replay_token" value="{{ replay_token }}">
        {% endif %}
        <div class="form-actions">
          {% if replay_token %}
          <button type="submit" class="stop-replay-button{% if replay_status != "running" %} is-hidden{% endif %}"
                  data-stop-replay formaction="{{ replay_stop_url }}"
                  {% if replay_status != "running" %}disabled{% endif %}>
            Stop Replay
          </button>
          <button type="submit" class="resume-replay-button{% if replay_status != "stopped" %} is-hidden{% endif %}"
                  data-resume-replay formaction="{{ replay_resume_url }}"
                  {% if replay_status != "stopped" %}disabled{% endif %}>
            Resume Replay
          </button>
          <button type="submit" class="restart-replay-button{% if replay_status not in ["stopped", "done"] %} is-hidden{% endif %}"
                  data-restart-replay formaction="{{ replay_url }}"
                  {% if replay_status not in ["stopped", "done"] %}disabled{% endif %}>
            Restart Replay
          </button>
          {% endif %}
          {% if not replay_token %}
          <button type="submit" class="start-replay-button" data-replay-start {% if not scan_token %}disabled{% endif %}>
            Start Replay
          </button>
          {% endif %}
        </div>
      </form>

      {% if replay_token %}
      <div data-replay-stream data-replay-token="{{ replay_token }}" data-replay-status-url="{{ replay_status_url }}">
        <div class="result info replay-status" data-replay-status>Starting replay…</div>
        <div class="progress-track" aria-hidden="true">
          <div class="progress-fill" data-replay-progress></div>
        </div>
        <div class="progress-meta">
          <span data-replay-progress-text>Sent 0 of {{ replay_total }}</span>
          <span data-replay-target>Target -</span>
          <span data-replay-eta>ETA -</span>
        </div>
      </div>
      {% endif %}
    </div>

    {% if log_lines or replay_token %}
    <div class="log-wrapper" data-log-section {% if replay_token %}data-live-replay="true"{% endif %}>
      <details class="log-block" open>
        <summary>Replay log</summary>
        {% if not replay_token %}
        <div class="log-controls">
          <label>
            Rows to display:
            <select data-table-limit>
              <option value="20">20</option>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="all">All</option>
            </select>
          </label>
        </div>
        {% endif %}
        <div style="overflow-x: auto;">
          <table class="log-table" {% if not replay_token %}data-sortable-table data-numeric-keys="index,sendTimeMs,fcnt,freq,size"{% endif %}>
            <thead>
              <tr>
                {% if replay_token %}
                <th>#</th>
                <th>Status</th>
                <th>Sent at</th>
                <th>Gateway EUI</th>
                <th>FCnt</th>
                <th>Frequency</th>
                <th>Size</th>
                <th>Message</th>
                {% else %}
                <th><button type="button" data-sort-key="index">#</button></th>
                <th><button type="button" data-sort-key="status">Status</button></th>
                <th><button type="button" data-sort-key="sendTimeMs">Sent at</button></th>
                <th><button type="button" data-sort-key="gateway">Gateway EUI</button></th>
                <th><button type="button" data-sort-key="fcnt">FCnt</button></th>
                <th><button type="button" data-sort-key="freq">Frequency</button></th>
                <th><button type="button" data-sort-key="size">Size</button></th>
                <th><button type="button" data-sort-key="message">Message</button></th>
                {% endif %}
              </tr>
            </thead>
            <tbody data-replay-log-body>
              {% for log_line in log_lines %}
              <tr class="{{ log_line.css }}"
                  data-index="{{ log_line.index }}"
                  data-status="{{ log_line.status }}"
                  data-send-time-ms="{{ log_line.send_time_ms or '' }}"
                  data-gateway="{{ log_line.gateway or '' }}"
                  data-fcnt="{{ log_line.fcnt or '' }}"
                  data-freq="{{ log_line.freq or '' }}"
                  data-size="{{ log_line.size or '' }}"
                  data-message="{{ (log_line.message or '') | e }}">
                <td>{{ log_line.index }}</td>
                <td>{{ log_line.status }}</td>
                <td class="send-time-cell">-</td>
                <td>{{ log_line.gateway or "-" }}</td>
                <td>{{ log_line.fcnt or "-" }}</td>
                <td>{{ log_line.freq or "-" }}</td>
                <td>{{ log_line.size or "-" }}</td>
                <td>{{ log_line.message }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </details>
    </div>
    {% endif %}

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  <div class="loading-overlay" data-loading-overlay hidden>
    <div class="loading-card">
      <div class="spinner" aria-hidden="true"></div>
      <div>Replaying uplinks…</div>
    </div>
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

SIMPLE_PAGE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ page_title }}</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1 class="page-title">{% if title_icon %}<span class="material-icons" aria-hidden="true">{{ title_icon }}</span>{% endif %}{{ title }}</h1>
          <p class="subtitle">{{ subtitle }}</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back</a>
      </div>
      {{ body_html|safe }}
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

LOGIN_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Sign in</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1 class="page-title"><span class="material-icons" aria-hidden="true">login</span>Sign in</h1>
          <p class="subtitle">Authenticate to access the Replay tool.</p>
        </div>
      </div>

      {% if error_message %}
      <div class="result error">{{ error_message }}</div>
      {% endif %}

      <form method="POST" action="{{ login_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div>
          <label for="username">Username</label>
          <input id="username" name="username" type="text" autocomplete="username" required>
        </div>
        <div>
          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required>
        </div>
        {% if next_url %}
        <input type="hidden" name="next" value="{{ next_url }}">
        {% endif %}
        <div class="form-actions">
          <button type="submit">Sign in</button>
        </div>
      </form>
    </div>
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

CHANGE_PASSWORD_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Change password</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1 class="page-title"><span class="material-icons" aria-hidden="true">lock</span>Change password</h1>
          <p class="subtitle">Set a new password to continue.</p>
        </div>
      </div>

      {% if error_message %}
      <div class="result error">{{ error_message }}</div>
      {% endif %}

      {% if success_message %}
      <div class="result success">{{ success_message }}</div>
      {% endif %}

      <form method="POST" action="{{ change_password_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div>
          <label for="current_password">Current password</label>
          <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
        </div>
        <div>
          <label for="new_password">New password</label>
          <div class="field-controls">
            <input id="new_password" name="new_password" type="text" autocomplete="new-password" data-password-input required>
            <div class="field-tools">
              <button type="button" class="icon-button" data-password-generate title="Generate password"><span class="material-icons" aria-hidden="true">autorenew</span></button>
              <button type="button" class="icon-button" data-password-copy title="Copy password"><span class="material-icons" aria-hidden="true">content_copy</span></button>
            </div>
          </div>
        </div>
        <div>
          <label for="confirm_password">Confirm new password</label>
          <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
        </div>
        <div class="form-actions">
          <button type="submit">Update password</button>
        </div>
      </form>
    </div>
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

DECODE_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Decrypt & Decode LoRaWAN Log</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1 class="page-title"><span class="material-icons" aria-hidden="true">lock_open</span>Decrypt &amp; Decode</h1>
          <p class="subtitle">Decrypt uplinks from <strong>{{ selected_filename }}</strong> and decode them with your payload decoder.</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back</a>
      </div>

      {% if summary_lines %}
      <div class="result {{ result_class }}">
        {% for line in summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      <div class="section-divider"></div>

      <div class="field-group">
        <div class="field-header">
          <label>Device session keys</label>
        </div>
        <div class="hint">Review the devices discovered in this logfile and edit credentials on the Device session keys page.</div>
        <div class="key-grid">
          {% for devaddr in devaddrs %}
          <div class="field-group">
            <div class="field-header">
              <label>{{ credentials.get(devaddr, {}).get('name', 'Device') }} — {{ devaddr }}
                {% if devaddr in missing_keys %}
                <span class="tag">Missing</span>
                {% endif %}
              </label>
            </div>
            <div class="hint">Session keys stored: {% if devaddr in missing_keys %}no{% else %}yes{% endif %}</div>
          </div>
          {% endfor %}
        </div>
        <div class="form-actions">
          <a class="secondary-button" href="{{ keys_url }}?scan_token={{ scan_token }}"><span class="material-icons" aria-hidden="true">settings</span>Manage Devices</a>
        </div>
      </div>

      {% if missing_keys %}
      <div class="section-divider"></div>

      <div class="field-group missing-keys-block">
        <div class="field-header">
          <label>Add missing devices</label>
        </div>
        <div class="hint">Add session keys for missing DevAddr entries so decoding can continue.</div>
        <div class="hint-divider" aria-hidden="true"></div>
      {% for devaddr in missing_keys %}
        <form method="POST" action="{{ decode_url }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <input type="hidden" name="scan_token" value="{{ scan_token }}">
          <input type="hidden" name="action" value="add_device">
          <input type="hidden" name="decoder_id" value="{{ selected_decoder }}">
          <div class="field-group">
            <div class="field-header">
              <label>DevAddr <span class="devaddr-label">{{ devaddr }}</span></label>
            </div>
            <div class="key-grid add-device-grid">
              <div>
                <label for="new_devaddr_{{ devaddr }}">DevAddr (hex)</label>
                <input id="new_devaddr_{{ devaddr }}" name="new_devaddr" type="text" value="{{ devaddr }}" readonly>
              </div>
              <div>
                <label for="new_name_{{ devaddr }}">Device name (optional)</label>
                <input id="new_name_{{ devaddr }}" name="new_name" type="text" placeholder="Wildlife collar 17">
              </div>
              <div>
                <label for="new_nwk_{{ devaddr }}">NwkSKey (hex)</label>
                <input id="new_nwk_{{ devaddr }}" name="new_nwk" type="password" placeholder="000102030405060708090A0B0C0D0E0F" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
              </div>
              <div>
                <label for="new_app_{{ devaddr }}">AppSKey (hex)</label>
                <input id="new_app_{{ devaddr }}" name="new_app" type="password" placeholder="F0E0D0C0B0A090807060504030201000" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
              </div>
            </div>
            <div class="form-actions">
              <button type="submit" class="primary-button"><span class="material-icons" aria-hidden="true">add</span>Add device</button>
            </div>
          </div>
        </form>
        {% endfor %}
      </div>

      <div class="section-divider"></div>
      {% else %}
      <div class="section-divider"></div>
      {% endif %}

      <form method="POST" action="{{ decode_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        <input type="hidden" name="action" value="decode">
        <input type="hidden" name="progress_id" value="" data-decode-progress-id>
        <div>
          <label for="decoder_id">Payload decoder</label>
          <select id="decoder_id" name="decoder_id" required>
            {% for decoder in decoders %}
            <option value="{{ decoder.id }}" {% if decoder.id == selected_decoder %}selected{% endif %}>{{ decoder.label }}</option>
            {% endfor %}
          </select>
          <div class="hint">Select the decoder and press Decode to process all decrypted payloads.</div>
          <div class="form-actions">
            <a class="secondary-button" href="{{ decoders_url }}"><span class="material-icons" aria-hidden="true">settings</span>Manage Decoders</a>
          </div>
        </div>
        <div class="form-actions">
          <button type="submit" class="start-replay-button" {% if missing_keys %}disabled{% endif %} data-show-decode-loader="true">Decode</button>
        </div>
        {% if missing_keys %}
        <div class="result error">Missing keys for {{ missing_keys|length }} DevAddr(s). Save keys before decoding.</div>
        {% endif %}
      </form>

      {% if decode_results %}
      <div class="section-divider"></div>
      <div class="log-wrapper" data-decode-section>
        <div class="table-actions decode-actions">
          <form method="POST" action="{{ decode_url }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="scan_token" value="{{ scan_token }}">
            <input type="hidden" name="action" value="save_results">
            <input type="hidden" name="decoder_id" value="{{ selected_decoder }}">
            <input type="hidden" name="export_token" value="{{ export_token }}">
            <button type="submit" class="secondary-button"><span class="material-icons" aria-hidden="true">save</span>Save results</button>
          </form>
          {% if export_csv_url %}
          <a class="secondary-button" href="{{ export_csv_url }}"><span class="material-icons" aria-hidden="true">file_download</span>Export CSV</a>
          {% endif %}
          {% if export_json_url %}
          <a class="secondary-button" href="{{ export_json_url }}"><span class="material-icons" aria-hidden="true">file_download</span>Export JSON</a>
          {% endif %}
          {% if analyze_url %}
          <a class="secondary-button" href="{{ analyze_url }}"><span class="material-icons" aria-hidden="true">analytics</span>Analyze results</a>
          {% endif %}
        </div>
        <details class="log-block" open>
          <summary>Decoded payloads</summary>
          <div class="log-controls">
            <label>
              Rows to display:
              <select data-table-limit>
                <option value="20">20</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="all">All</option>
              </select>
            </label>
          </div>
          <div style="overflow-x: auto;">
            <table class="log-table" data-sortable-table data-default-sort-key="timeUnix" data-numeric-keys="index,fcnt,fport,timeUnix">
              <thead>
                <tr>
                  <th><button type="button" data-sort-key="index">#</button></th>
                  <th><button type="button" data-sort-key="status">Status</button></th>
                  <th><button type="button" data-sort-key="devaddr">DevAddr</button></th>
                  <th><button type="button" data-sort-key="fcnt">FCnt</button></th>
                  <th><button type="button" data-sort-key="fport">FPort</button></th>
                  <th><button type="button" data-sort-key="time">Time parsed</button></th>
                  <th><button type="button" data-sort-key="timeUnix">Timestamp</button></th>
                  <th>Time (UTC)</th>
                  {% for column in decode_columns %}
                  <th>{{ column.label }}</th>
                  {% endfor %}
                  <th>Payload</th>
                  <th>Decoded</th>
                </tr>
              </thead>
              <tbody>
                {% for row in decode_results %}
                <tr class="{{ row.css }}"
                    data-index="{{ row.index }}"
                    data-status="{{ row.status }}"
                    data-devaddr="{{ row.devaddr }}"
                    data-fcnt="{{ row.fcnt }}"
                    data-fport="{{ row.fport }}"
                    data-time="{{ row.time }}"
                    data-time-unix="{{ row.time_unix }}"
                    data-time-utc="{{ row.time_utc }}"
                    data-payload="{{ row.payload_hex | e }}"
                    data-decoded="{{ row.decoded_preview | e }}">
                  <td>{{ row.index }}</td>
                  <td>{{ row.status }}</td>
                  <td>{{ row.devaddr }}</td>
                  <td>{{ row.fcnt }}</td>
                  <td>{{ row.fport }}</td>
                  <td>{{ row.time }}</td>
                  <td>{{ row.time_unix }}</td>
                  <td>{{ row.time_utc }}</td>
                  {% for column in decode_columns %}
                  <td>{{ row.decoded_flat.get(column.key, "") }}</td>
                  {% endfor %}
                  <td>
                    <button type="button" class="cell-action" data-detail-trigger>
                      Payload ({{ row.payload_hex|length }} bytes)
                    </button>
                  </td>
                  <td>
                    <button type="button" class="cell-action" data-detail-trigger>
                      Decoded view
                    </button>
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </details>
      </div>
      {% endif %}
    </div>

    <div class="detail-overlay" data-detail-overlay hidden>
      <div class="detail-card">
        <h2 data-detail-title>Packet details</h2>
        <div class="detail-grid" data-detail-meta></div>
        <div class="detail-collapsible">
          <details open>
            <summary>Payload</summary>
            <div class="detail-block"><pre data-detail-payload></pre></div>
          </details>
        </div>
        <div class="detail-collapsible">
          <details open>
            <summary>Decoded (JSON)</summary>
            <div class="detail-block"><pre data-detail-decoded></pre></div>
          </details>
        </div>
        <div class="detail-actions">
          <button type="button" data-detail-close>Close</button>
        </div>
      </div>
    </div>
    <div class="loading-overlay" data-decode-overlay data-decode-progress-url="{{ decode_progress_url }}" hidden>
      <div class="loading-card">
        <div class="progress-track" aria-hidden="true">
          <div class="progress-fill" data-decode-progress></div>
        </div>
        <div class="progress-meta">
          <span data-decode-progress-text>Preparing decode…</span>
          <span class="progress-percent" data-decode-progress-percent>0%</span>
        </div>
      </div>
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  {{ script_block|safe }}
</body>
</html>
"""

DEVICE_KEYS_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Device Session Keys</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1 class="page-title"><span class="material-icons" aria-hidden="true">memory</span>Devices</h1>
          <p class="subtitle">Store DevAddr, optional names, and ABP session keys for decoding.</p>
        </div>
        <a class="secondary-button" href="{{ back_url }}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back</a>
      </div>

      {% if summary_lines %}
      <div class="result {{ result_class }}">
        {% for line in summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      {% endif %}

      <form method="POST" action="{{ keys_url }}" data-delete-form>
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        <input type="hidden" name="action" value="delete_device">
        <input type="hidden" name="delete_devaddr" value="" data-delete-input>
      </form>

      <form method="POST" action="{{ keys_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        <input type="hidden" name="action" value="save_keys">
        <div class="field-group">
          <div class="field-header">
            <label>Known devices</label>
          </div>
          <div class="hint">Update keys or friendly names for devices already stored.</div>
          <div class="device-rows">
            {% for devaddr in known_devaddrs %}
            <div class="device-row">
              <div class="field-header">
                <label>DevAddr <span class="devaddr-label">{{ devaddr }}</span></label>
              </div>
              <div class="key-grid device-grid">
                <div>
                  <label for="name_{{ devaddr }}">Device name</label>
                  <input id="name_{{ devaddr }}" name="name_{{ devaddr }}" type="text" value="{{ credentials.get(devaddr, {}).get('name', '') }}">
                </div>
                <div>
                  <label for="nwk_{{ devaddr }}">NwkSKey</label>
                  <div class="field-controls key-controls">
                    <input class="input-with-actions key-input" id="nwk_{{ devaddr }}" name="nwk_{{ devaddr }}" type="password" value="{{ credentials.get(devaddr, {}).get('nwk_skey', '') }}" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
                    <button type="button" class="toggle-visibility" data-toggle-visibility="nwk_{{ devaddr }}" aria-pressed="false" title="Show key"><span class="material-icons" aria-hidden="true">visibility</span></button>
                  </div>
                </div>
                <div>
                  <label for="app_{{ devaddr }}">AppSKey</label>
                  <div class="field-controls key-controls">
                    <input class="input-with-actions key-input" id="app_{{ devaddr }}" name="app_{{ devaddr }}" type="password" value="{{ credentials.get(devaddr, {}).get('app_skey', '') }}" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
                    <button type="button" class="toggle-visibility" data-toggle-visibility="app_{{ devaddr }}" aria-pressed="false" title="Show key"><span class="material-icons" aria-hidden="true">visibility</span></button>
                  </div>
                </div>
                <div class="remove-cell">
                  <button type="button" class="danger-button" data-delete-devaddr="{{ devaddr }}" title="Remove device" aria-label="Remove device">
                    <span class="material-icons" aria-hidden="true">delete</span>
                  </button>
                </div>
              </div>
            </div>
            {% endfor %}
          </div>
        </div>
        <div class="form-actions">
          <button type="submit" class="primary-button"><span class="material-icons" aria-hidden="true">save</span>Save updates</button>
        </div>
      </form>

      <div class="section-divider"></div>

      <form method="POST" action="{{ keys_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% if scan_token %}
        <input type="hidden" name="scan_token" value="{{ scan_token }}">
        {% endif %}
        <input type="hidden" name="action" value="add_device">
        <div class="field-group">
          <div class="field-header">
            <label>Add a new device</label>
          </div>
          <div class="hint">Add a DevAddr upfront so it is ready for future logfiles.</div>
          <div class="key-grid add-device-grid">
            <div>
              <label for="new_devaddr">DevAddr (hex)</label>
              <input id="new_devaddr" name="new_devaddr" type="text" placeholder="26011BDA">
            </div>
            <div>
              <label for="new_name">Device name (optional)</label>
              <input id="new_name" name="new_name" type="text" placeholder="Wildlife collar 17">
            </div>
            <div>
              <label for="new_nwk">NwkSKey (hex)</label>
              <input id="new_nwk" name="new_nwk" type="password" placeholder="000102030405060708090A0B0C0D0E0F" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
            </div>
            <div>
              <label for="new_app">AppSKey (hex)</label>
              <input id="new_app" name="new_app" type="password" placeholder="F0E0D0C0B0A090807060504030201000" pattern="[0-9A-Fa-f]{32}" minlength="32" maxlength="32" title="32 hex characters" autocomplete="off" spellcheck="false">
            </div>
          </div>
        </div>
        <div class="form-actions">
          <button type="submit" class="primary-button"><span class="material-icons" aria-hidden="true">add</span>Add device</button>
        </div>
      </form>
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  {% if scan_summary_lines %}
  <div class="scan-overlay" data-scan-overlay>
    <div class="scan-card">
      <h2>Scan results{% if scan_filename %} — {{ scan_filename }}{% endif %}</h2>
      <div class="result success">
        {% for line in scan_summary_lines %}
        <div>{{ line }}</div>
        {% endfor %}
      </div>
      <div class="form-actions">
        <button type="button" data-scan-close>Close</button>
      </div>
    </div>
  </div>
  {% endif %}
  {{ script_block|safe }}
</body>
</html>
"""

GENERATOR_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Generate LoRaWAN Test Log</title>
  <link rel="icon" type="image/x-icon" href="{{ favicon_url }}">
  {{ style_block|safe }}
</head>
<body>
  <div class="outer-column">
    {{ nav_html|safe }}

    <div class="card">
      <div class="card-header">
        <div>
          <h1 class="page-title"><span class="material-icons" aria-hidden="true">description</span>Generate Test Logfile</h1>
          <p class="subtitle">Configure LoRaWAN ABP parameters and download a JSON Lines log.</p>
        </div>
        <a class="secondary-button" href="{{ files_url }}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back to Files</a>
      </div>

      <form method="POST" action="{{ generator_url }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div class="field-group">
          <div class="field-header">
            <label for="gateway_eui">Gateway EUI</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="gateway_eui" name="gateway_eui" type="text" value="{{ form_values.gateway_eui }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('gateway_eui', 'gateway_eui')" title="Generate Gateway EUI"><span class="material-icons" aria-hidden="true">autorenew</span></button>
              <button type="button" class="icon-button" onclick="copyField('gateway_eui')" title="Copy Gateway EUI"><span class="material-icons" aria-hidden="true">content_copy</span></button>
            </div>
          </div>
          <div class="hint">16 hex characters, e.g. 0102030405060708.</div>
        </div>

        <div class="field-group">
          <div class="field-header">
            <label for="devaddr_hex">DevAddr (hex, big-endian)</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="devaddr_hex" name="devaddr_hex" type="text" value="{{ form_values.devaddr_hex }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('devaddr_hex', 'devaddr')" title="Generate DevAddr"><span class="material-icons" aria-hidden="true">autorenew</span></button>
              <button type="button" class="icon-button" onclick="copyField('devaddr_hex')" title="Copy DevAddr"><span class="material-icons" aria-hidden="true">content_copy</span></button>
            </div>
          </div>
        </div>

        <div class="field-group">
          <div class="field-header">
            <label for="nwk_skey_hex">NwkSKey (hex)</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="nwk_skey_hex" name="nwk_skey_hex" type="text" value="{{ form_values.nwk_skey_hex }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('nwk_skey_hex', 'skey')" title="Generate NwkSKey"><span class="material-icons" aria-hidden="true">autorenew</span></button>
              <button type="button" class="icon-button" onclick="copyField('nwk_skey_hex')" title="Copy NwkSKey"><span class="material-icons" aria-hidden="true">content_copy</span></button>
            </div>
          </div>
        </div>

        <div class="field-group">
          <div class="field-header">
            <label for="app_skey_hex">AppSKey (hex)</label>
          </div>
          <div class="field-controls">
            <input class="input-with-actions" id="app_skey_hex" name="app_skey_hex" type="text" value="{{ form_values.app_skey_hex }}" required>
            <div class="field-tools">
              <button type="button" class="icon-button" onclick="generateField('app_skey_hex', 'skey')" title="Generate AppSKey"><span class="material-icons" aria-hidden="true">autorenew</span></button>
              <button type="button" class="icon-button" onclick="copyField('app_skey_hex')" title="Copy AppSKey"><span class="material-icons" aria-hidden="true">content_copy</span></button>
            </div>
          </div>
        </div>

        <div>
          <label for="fport">FPort</label>
          <input id="fport" name="fport" type="number" min="1" max="223" value="{{ form_values.fport }}" required>
        </div>

        <div>
          <label for="app_payload_hex">Application payload (hex)</label>
          <input id="app_payload_hex" name="app_payload_hex" type="text" value="{{ form_values.app_payload_hex }}" required>
          <div class="hint">Byte payload encoded as hex (e.g. 0102030405060708).</div>
          <div class="payload-examples">
            <label for="payload_example">Example payloads (optional)</label>
            <select id="payload_example" data-payload-example>
              <option value="">Choose an example payload...</option>
              {% for example in payload_examples %}
              <option value="{{ example.payload }}" data-port="{{ example.port }}">{{ example.label }}</option>
              {% endfor %}
            </select>
            <div class="hint">Selecting an example fills both payload and matching FPort.</div>
          </div>
        </div>

        <div>
          <label for="fcnt_start">Frame counter start</label>
          <input id="fcnt_start" name="fcnt_start" type="number" value="{{ form_values.fcnt_start }}" min="0" required>
        </div>

        <div>
          <label for="num_frames">Number of frames</label>
          <input id="num_frames" name="num_frames" type="number" value="{{ form_values.num_frames }}" min="1" required>
        </div>

        <div>
          <label for="freq_mhz">Frequency (MHz)</label>
          <select id="freq_mhz" name="freq_mhz" required>
            {% for freq in freq_options %}
            <option value="{{ freq }}" {% if form_values.freq_mhz == freq %}selected{% endif %}>{{ freq }} MHz</option>
            {% endfor %}
          </select>
        </div>

        <div>
          <label for="datarate">Data rate</label>
          <select id="datarate" name="datarate" required>
            {% for dr in datarate_options %}
            <option value="{{ dr }}" {% if form_values.datarate == dr %}selected{% endif %}>{{ dr }}</option>
            {% endfor %}
          </select>
        </div>

        <div>
          <label for="coding_rate">Coding rate</label>
          <select id="coding_rate" name="coding_rate" required>
            {% for cr in coding_rate_options %}
            <option value="{{ cr }}" {% if form_values.coding_rate == cr %}selected{% endif %}>{{ cr }}</option>
            {% endfor %}
          </select>
        </div>

        <div>
          <label for="start_time">Start time (UTC)</label>
          <input id="start_time" name="start_time" type="datetime-local" value="{{ form_values.start_time }}" required>
        </div>

        <div>
          <label for="interval_seconds">Interval between frames (seconds)</label>
          <input id="interval_seconds" name="interval_seconds" type="number" min="1" value="{{ form_values.interval_seconds }}" required>
        </div>

        <div>
          <label for="out_file">Download filename</label>
          <input id="out_file" name="out_file" type="text" value="{{ form_values.out_file }}" required>
        </div>

        {% if error_message %}
        <div class="result error">{{ error_message }}</div>
        {% endif %}

        <div class="form-actions">
          <button type="submit">Generate</button>
          <a class="secondary-button" href="{{ files_url }}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back to Files</a>
        </div>
      </form>
    </div>

    <p class="brand-note">
      A Smart Parks tool to Protect Wildlife with Passion and Technology.
      <a href="https://www.smartparks.org" target="_blank" rel="noopener">www.smartparks.org</a>
    </p>
  </div>
  {% if generated_entry %}
  <div class="scan-overlay" data-generated-overlay data-generated-download-url="{{ generated_download_url }}" data-generated-filename="{{ generated_filename }}">
    <div class="scan-card">
      <h2>Test log generated</h2>
      <div class="result success">
        <div>File generated, stored, and downloaded.</div>
        {% if generated_filename %}
        <div>{{ generated_filename }}</div>
        {% endif %}
      </div>
      <div class="form-actions">
        {% if generated_scan_token %}
        <a class="secondary-button" href="{{ replay_url }}?scan_token={{ generated_scan_token }}"><span class="material-icons" aria-hidden="true">play_arrow</span>Replay</a>
        <a class="secondary-button" href="{{ decode_url }}?scan_token={{ generated_scan_token }}"><span class="material-icons" aria-hidden="true">lock_open</span>Decrypt &amp; Decode</a>
        {% else %}
        <button type="button" class="secondary-button" disabled><span class="material-icons" aria-hidden="true">play_arrow</span>Replay</button>
        <button type="button" class="secondary-button" disabled><span class="material-icons" aria-hidden="true">lock_open</span>Decrypt &amp; Decode</button>
        {% endif %}
        <button type="button" data-generated-close>Close</button>
      </div>
    </div>
  </div>
  {% endif %}
  {{ script_block|safe }}
</body>
</html>
"""

LOG_GENERATOR_DEFAULTS = {
    "gateway_eui": "0102030405060708",
    "devaddr_hex": "26011BDA",
    "nwk_skey_hex": "000102030405060708090A0B0C0D0E0F",
    "app_skey_hex": "F0E0D0C0B0A090807060504030201000",
    "app_payload_hex": "0102030405060708",
    "fcnt_start": "0",
    "num_frames": "100",
    "freq_mhz": "868.3",
    "datarate": "SF7BW125",
    "coding_rate": "4/5",
    "fport": "1",
    "start_time": "2025-01-01T12:00",
    "interval_seconds": "10",
    "out_file": "example_log_abp.jsonl",
}

PAYLOAD_EXAMPLES = [
    {
        "label": "Port 2 — f21e0100005300b3a40d1f4a110e0329fa000003051e0004f37a256900000000",
        "port": "2",
        "payload": "f21e0100005300b3a40d1f4a110e0329fa000003051e0004f37a256900000000",
    },
    {
        "label": "Port 4 — f40e04209300950f7d7f8b176f550002",
        "port": "4",
        "payload": "f40e04209300950f7d7f8b176f550002",
    },
    {
        "label": "Port 13 — 930ef77a2569b3a40d1f4a110e031e00",
        "port": "13",
        "payload": "930ef77a2569b3a40d1f4a110e031e00",
    },
]

EU868_FREQ_OPTIONS = [
    "868.1",
    "868.3",
    "868.5",
    "867.1",
    "867.3",
    "867.5",
    "867.7",
    "867.9",
]

EU868_DATARATE_OPTIONS = [
    "SF12BW125",
    "SF11BW125",
    "SF10BW125",
    "SF9BW125",
    "SF8BW125",
    "SF7BW125",
    "SF7BW250",
]

EU868_CODING_RATE_OPTIONS = ["4/5", "4/6", "4/7", "4/8"]


def get_generator_form_values(overrides=None):
    values = dict(LOG_GENERATOR_DEFAULTS)
    if overrides:
        for key in values.keys():
            if key in overrides:
                values[key] = overrides[key]
    return values


def clean_hex(value: str) -> str:
    return value.replace(" ", "").replace(":", "").replace("-", "").strip()


def ensure_data_dirs():
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
    os.makedirs(DECODER_DIR, mode=0o700, exist_ok=True)
    os.makedirs(DECODE_RESULTS_DIR, mode=0o700, exist_ok=True)
    os.makedirs(BUILTIN_DECODER_DIR, exist_ok=True)


def load_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default


def save_json_file(path, data):
    ensure_data_dirs()
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    os.replace(tmp_path, path)


def list_stored_logs():
    entries = load_json_file(UPLOAD_INDEX_PATH, [])
    available = []
    for entry in entries:
        if os.path.exists(entry.get("path", "")):
            available.append(entry)
    return available


def get_stored_log_entry(log_id):
    for entry in list_stored_logs():
        if entry.get("id") == log_id:
            return entry
    return None


def store_uploaded_log(logfile, owner):
    ensure_data_dirs()
    token = secrets.token_urlsafe(8)
    filename = secure_filename(logfile.filename or "log.jsonl") or "log.jsonl"
    stored_name = f"{token}_{filename}"
    path = os.path.join(UPLOAD_DIR, stored_name)
    logfile.save(path)
    size = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    entry = {
        "id": token,
        "filename": filename,
        "path": path,
        "size": size,
        "owner": owner,
        "uploaded_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    entries = load_json_file(UPLOAD_INDEX_PATH, [])
    entries.insert(0, entry)
    save_json_file(UPLOAD_INDEX_PATH, entries[:200])
    return entry


def store_generated_log(buffer, filename, owner):
    ensure_data_dirs()
    token = secrets.token_urlsafe(8)
    filename = secure_filename(filename or "log.jsonl") or "log.jsonl"
    stored_name = f"{token}_{filename}"
    path = os.path.join(UPLOAD_DIR, stored_name)
    with open(path, "wb") as handle:
        handle.write(buffer.getvalue())
    size = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    entry = {
        "id": token,
        "filename": filename,
        "path": path,
        "size": size,
        "owner": owner,
        "uploaded_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    entries = load_json_file(UPLOAD_INDEX_PATH, [])
    entries.insert(0, entry)
    save_json_file(UPLOAD_INDEX_PATH, entries[:200])
    return entry


def delete_stored_log(log_id):
    entries = load_json_file(UPLOAD_INDEX_PATH, [])
    kept = []
    removed_path = None
    for entry in entries:
        if entry.get("id") == log_id:
            removed_path = entry.get("path")
        else:
            kept.append(entry)
    save_json_file(UPLOAD_INDEX_PATH, kept)
    if removed_path and os.path.exists(removed_path):
        os.remove(removed_path)
    return removed_path is not None


def list_saved_decode_results():
    entries = load_json_file(DECODE_RESULTS_INDEX_PATH, [])
    available = []
    for entry in entries:
        if os.path.exists(entry.get("path", "")):
            available.append(entry)
    return available


def get_saved_decode_result_entry(saved_id):
    for entry in list_saved_decode_results():
        if entry.get("id") == saved_id:
            return entry
    return None


def load_saved_decode_rows(saved_id):
    entry = get_saved_decode_result_entry(saved_id)
    if not entry:
        return None, None
    try:
        with open(entry["path"], "r", encoding="utf-8") as handle:
            rows = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return entry, None
    return entry, rows


def store_saved_decode_result(rows, log_id, filename, decoder_id, owner):
    ensure_data_dirs()
    token = secrets.token_urlsafe(8)
    stored_name = f"{token}_decoded.json"
    path = os.path.join(DECODE_RESULTS_DIR, stored_name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2, ensure_ascii=True)
    size = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    entry = {
        "id": token,
        "log_id": log_id,
        "filename": filename,
        "path": path,
        "size": size,
        "decoder_id": decoder_id,
        "owner": owner,
        "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    entries = load_json_file(DECODE_RESULTS_INDEX_PATH, [])
    entries.insert(0, entry)
    save_json_file(DECODE_RESULTS_INDEX_PATH, entries[:200])
    return entry


def scan_stored_log(log_id):
    entry = get_stored_log_entry(log_id)
    if not entry:
        raise ValueError("Log file not found.")
    with open(entry["path"], "rb") as handle:
        parsed, gateways, devaddrs, scan_errors = scan_logfile(handle)
    if scan_errors:
        preview = scan_errors[:10]
        error_lines = [
            "Logfile scan summary:",
            f"Uplinks (valid)={len(parsed)}",
            format_list("Gateway EUI", gateways),
            format_list("DevAddr (hex)", devaddrs),
            f"Validation errors={len(scan_errors)}.",
        ]
        error_lines.extend(preview)
        if len(scan_errors) > len(preview):
            error_lines.append(f"... (+{len(scan_errors) - len(preview)} more)")
        raise ValueError("\n".join(error_lines))
    if not parsed:
        raise ValueError("No valid uplinks found.")
    scan_token = store_scan_result(parsed, gateways, devaddrs, entry["filename"], entry["id"])
    return scan_token, entry


def load_credentials():
    return load_json_file(CREDENTIALS_PATH, {})


def save_credentials(credentials):
    save_json_file(CREDENTIALS_PATH, credentials)


def normalize_skey(value, label):
    cleaned = clean_hex(value).upper()
    if len(cleaned) != 32:
        raise ValueError(f"{label} must be 16 bytes (32 hex chars).")
    return cleaned


def normalize_devaddr(value):
    cleaned = clean_hex(value).upper()
    if len(cleaned) != 8:
        raise ValueError("DevAddr must be 4 bytes (8 hex chars).")
    return cleaned


def generate_logfile_bytes(form_values):
    gateway_eui = form_values["gateway_eui"].strip()
    if not gateway_eui:
        raise ValueError("Gateway EUI is required.")

    devaddr_hex = form_values["devaddr_hex"].strip()
    nwk_skey_hex = form_values["nwk_skey_hex"].strip()
    app_skey_hex = form_values["app_skey_hex"].strip()
    app_payload_hex = clean_hex(form_values["app_payload_hex"])
    if not app_payload_hex:
        raise ValueError("Application payload must be provided.")

    try:
        devaddr_le = make_test_log.devaddr_be_to_le(devaddr_hex)
        nwk_skey = make_test_log.hex_to_bytes(nwk_skey_hex, 16)
        app_skey = make_test_log.hex_to_bytes(app_skey_hex, 16)
        app_payload = bytes.fromhex(app_payload_hex)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    fcnt_start = parse_int(form_values["fcnt_start"], "Frame counter start", minimum=0)
    num_frames = parse_int(form_values["num_frames"], "Number of frames", minimum=1)
    interval_seconds = parse_int(form_values["interval_seconds"], "Interval between frames", minimum=1)

    freq_choice = form_values["freq_mhz"].strip()
    if freq_choice not in EU868_FREQ_OPTIONS:
        raise ValueError("Select a valid EU868 frequency.")
    freq_mhz = float(freq_choice)

    datarate = form_values["datarate"].strip()
    if datarate not in EU868_DATARATE_OPTIONS:
        raise ValueError("Select a valid EU868 data rate.")

    coding_rate = form_values["coding_rate"].strip()
    if coding_rate not in EU868_CODING_RATE_OPTIONS:
        raise ValueError("Select a valid coding rate.")

    start_time_raw = form_values["start_time"].strip()
    if not start_time_raw:
        raise ValueError("Start time is required.")
    try:
        start_time = datetime.datetime.fromisoformat(start_time_raw)
    except ValueError as exc:
        raise ValueError("Start time must be in YYYY-MM-DDTHH:MM format.") from exc

    out_file = form_values["out_file"].strip() or "generated_log.jsonl"

    output = io.StringIO()
    for i in range(num_frames):
        fcnt = fcnt_start + i
        fport = parse_int(form_values.get("fport", "1"), "FPort", minimum=1, maximum=223)
        phy = make_test_log.build_abp_uplink(
            devaddr_le=devaddr_le,
            nwk_skey=nwk_skey,
            app_skey=app_skey,
            fcnt=fcnt,
            app_payload=app_payload,
            fport=fport,
            confirmed=False,
        )

        base64_payload = base64.b64encode(phy).decode("ascii")
        timestamp = start_time + datetime.timedelta(seconds=i * interval_seconds)
        rxpk = {
            "time": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tmst": 1000000 + i * 1000,
            "freq": freq_mhz,
            "chan": 0,
            "rfch": 0,
            "stat": 1,
            "modu": "LORA",
            "datr": datarate,
            "codr": coding_rate,
            "rssi": -60 - (i % 20),
            "lsnr": 5.5 - (i % 10) * 0.1,
            "size": len(phy),
            "data": base64_payload,
        }
        rec = {"gatewayEui": gateway_eui, "rxpk": rxpk}
        output.write(json.dumps(rec) + "\n")

    buffer = io.BytesIO(output.getvalue().encode("utf-8"))
    buffer.seek(0)
    return buffer, out_file


def parse_int(value, field, minimum=None, maximum=None):
    try:
        num = int(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an integer.") from exc
    if minimum is not None and num < minimum:
        raise ValueError(f"{field} must be >= {minimum}.")
    if maximum is not None and num > maximum:
        raise ValueError(f"{field} must be <= {maximum}.")
    return num


def hex_to_bytes(value, label):
    cleaned = clean_hex(value)
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{label} must be valid hex.") from exc
    if len(raw) != 16:
        raise ValueError(f"{label} must be 16 bytes (32 hex chars).")
    return raw


def parse_uplink(rxpk):
    data = rxpk.get("data")
    if not data:
        raise ValueError("Missing rxpk.data payload.")
    try:
        phy = base64.b64decode(data, validate=True)
    except binascii.Error as exc:
        raise ValueError("rxpk.data is not valid base64.") from exc
    if len(phy) < 12:
        raise ValueError("PHYPayload too short.")

    mhdr = phy[0]
    mtype = (mhdr >> 5) & 0x07
    if mtype not in (2, 4):
        raise ValueError("PHYPayload is not an uplink data frame.")

    mac_payload = phy[1:-4]
    if len(mac_payload) < 7:
        raise ValueError("MACPayload too short.")

    devaddr_le = mac_payload[0:4]
    devaddr = devaddr_le[::-1].hex().upper()
    fctrl = mac_payload[4]
    fcnt = int.from_bytes(mac_payload[5:7], "little")
    fopts_len = fctrl & 0x0F

    fhdr_len = 7 + fopts_len
    if len(mac_payload) < fhdr_len:
        raise ValueError("FHDR length mismatch.")

    fopts = mac_payload[7:7 + fopts_len]
    remaining = mac_payload[fhdr_len:]
    fport = None
    frm_payload = b""
    if remaining:
        fport = remaining[0]
        frm_payload = remaining[1:]

    return {
        "mhdr": mhdr,
        "mtype": mtype,
        "devaddr": devaddr,
        "devaddr_le": devaddr_le,
        "fctrl": fctrl,
        "fcnt": fcnt,
        "fopts": fopts,
        "fport": fport,
        "frm_payload": frm_payload,
    }


def format_unix_utc(timestamp):
    if timestamp is None or timestamp == "":
        return ""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return ""
    try:
        return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def unpack_port29_messages(payload):
    if not payload:
        return []
    messages = []
    i = 0
    msg_len = len(payload)
    while i < msg_len - 7:
        if i + 3 > msg_len:
            raise ValueError("Port 29 message header incomplete.")
        port = payload[i]
        length = payload[i + 2]
        end = i + length + 3
        if end > msg_len:
            raise ValueError("Port 29 message length exceeds payload.")
        msg = payload[i + 1:end]
        i = end
        if i + 4 > msg_len:
            raise ValueError("Port 29 timestamp missing.")
        timestamp = (
            (payload[i + 3] << 24)
            | (payload[i + 2] << 16)
            | (payload[i + 1] << 8)
            | payload[i]
        ) & 0xFFFFFFFF
        i += 4
        messages.append({"port": port, "payload": bytes(msg), "timestamp": timestamp})
    return messages


def flatten_decoded(value, prefix="data", out=None):
    if out is None:
        out = {}
    if value is None:
        return out
    if isinstance(value, dict):
        for key, subvalue in value.items():
            key_str = str(key)
            next_prefix = f"{prefix}.{key_str}" if prefix else key_str
            flatten_decoded(subvalue, next_prefix, out)
        return out
    if isinstance(value, (list, tuple)):
        for idx, subvalue in enumerate(value):
            next_prefix = f"{prefix}.{idx}" if prefix else str(idx)
            flatten_decoded(subvalue, next_prefix, out)
        return out
    out[prefix] = value
    return out


def load_field_meta():
    if not os.path.exists(FIELD_META_PATH):
        return {}
    try:
        with open(FIELD_META_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def extract_field_key(column):
    if column.startswith("data."):
        return column.split(".", 1)[1]
    return column


def build_decode_columns_meta(columns, field_meta):
    columns_set = set(columns)
    ordered = []
    used = set()
    for key in field_meta.keys():
        col = f"data.{key}"
        if col in columns_set:
            ordered.append(col)
            used.add(col)
    for col in columns:
        if col not in used:
            ordered.append(col)
            used.add(col)
    meta_list = []
    for col in ordered:
        field_key = extract_field_key(col)
        meta = field_meta.get(field_key, {})
        label = field_key
        unit = meta.get("unit") or {}
        symbol = unit.get("symbol")
        if symbol:
            label = f"{field_key} ({symbol})"
        meta_list.append(
            {
                "key": col,
                "label": label,
                "group": meta.get("group", ""),
                "precision": meta.get("precision"),
                "isInteger": meta.get("isInteger"),
            }
        )
    return meta_list


FIELD_META = load_field_meta()


def lorawan_decrypt_payload(key, devaddr_le, fcnt, payload, direction=0):
    if not payload:
        return b""
    cipher = make_aes_cipher(key)
    out = bytearray()
    block_count = (len(payload) + 15) // 16
    for i in range(block_count):
        a_block = bytearray(16)
        a_block[0] = 0x01
        a_block[5] = direction & 0x01
        a_block[6:10] = devaddr_le
        a_block[10:14] = fcnt.to_bytes(4, "little")
        a_block[15] = i + 1
        s_block = cipher.encrypt(bytes(a_block))
        start = i * 16
        end = start + 16
        block = payload[start:end]
        for j, b in enumerate(block):
            out.append(b ^ s_block[j])
    return bytes(out)


def make_aes_cipher(key):
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError("PyCryptodome is required for LoRaWAN decryption.") from exc
    return AES.new(key, AES.MODE_ECB)


def extract_devaddr(rxpk):
    data = rxpk.get("data")
    if not data:
        raise ValueError("Missing rxpk.data payload.")
    try:
        payload = base64.b64decode(data, validate=True)
    except binascii.Error as exc:
        raise ValueError("rxpk.data is not valid base64.") from exc
    if len(payload) < 5:
        raise ValueError("PHYPayload too short to contain a DevAddr.")
    devaddr_le = payload[1:5]
    return devaddr_le[::-1].hex().upper()


def scan_logfile(stream):
    parsed = []
    gateways = set()
    devaddrs = set()
    errors = []

    for line_no, raw_line in enumerate(stream, start=1):
        if isinstance(raw_line, str):
            raw_line = raw_line.encode("utf-8")
        try:
            line = raw_line.decode("utf-8").strip()
        except UnicodeDecodeError:
            errors.append(f"Line {line_no}: invalid UTF-8 encoding.")
            continue

        if not line:
            continue

        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"Line {line_no}: JSON decode error ({exc}).")
            continue

        if not isinstance(rec, dict):
            errors.append(f"Line {line_no}: expected an object.")
            continue

        gateway_eui = rec.get("gatewayEui") or rec.get("gateway_eui")
        rxpk = rec.get("rxpk")
        if not gateway_eui or not isinstance(rxpk, dict):
            errors.append(f"Line {line_no}: missing gatewayEui or rxpk.")
            continue

        try:
            normalize_gateway_eui(gateway_eui)
        except ValueError as exc:
            errors.append(f"Line {line_no}: {exc}")
            continue

        try:
            devaddr = extract_devaddr(rxpk)
        except ValueError as exc:
            errors.append(f"Line {line_no}: {exc}")
            continue

        gateways.add(gateway_eui)
        devaddrs.add(devaddr)
        parsed.append({"gateway_eui": gateway_eui, "rxpk": rxpk})

    return parsed, sorted(gateways), sorted(devaddrs), errors


def prune_scan_cache(now=None):
    if not SCAN_CACHE:
        return
    now = time.time() if now is None else now
    expired = [token for token, entry in SCAN_CACHE.items() if now - entry["ts"] > SCAN_CACHE_TTL]
    for token in expired:
        del SCAN_CACHE[token]


def prune_decode_cache(now=None):
    if not DECODE_CACHE:
        return
    now = time.time() if now is None else now
    expired = [token for token, entry in DECODE_CACHE.items() if now - entry["ts"] > DECODE_CACHE_TTL]
    for token in expired:
        del DECODE_CACHE[token]


def set_decode_progress(progress_id, user_id, completed, total, done=False):
    if not progress_id:
        return
    DECODE_PROGRESS[progress_id] = {
        "user_id": user_id,
        "completed": completed,
        "total": total,
        "done": done,
        "ts": time.time(),
    }


def get_decode_progress(progress_id, user_id):
    entry = DECODE_PROGRESS.get(progress_id)
    if not entry or entry.get("user_id") != user_id:
        return None
    return entry


def prune_replay_cache(now=None):
    if not REPLAY_CACHE:
        return
    now = time.time() if now is None else now
    expired = [token for token, entry in REPLAY_CACHE.items() if now - entry["ts"] > REPLAY_CACHE_TTL]
    for token in expired:
        del REPLAY_CACHE[token]


def resolve_back_url(default_url):
    referrer = request.referrer or ""
    if not referrer:
        return default_url
    if referrer == request.url:
        return default_url
    parsed = urllib.parse.urlparse(referrer)
    host = urllib.parse.urlparse(request.host_url)
    if parsed.netloc and parsed.netloc != host.netloc:
        return default_url
    if parsed.scheme and parsed.scheme != host.scheme:
        return default_url
    blocked_paths = {
        "/scan",
        "/files/delete",
        "/replay/stop",
        "/replay/resume",
        "/replay/status",
    }
    if parsed.path in blocked_paths:
        return default_url
    return referrer


def store_replay_job(
    total,
    host,
    port,
    delay_ms,
    start_index=0,
    sent=0,
    errors=0,
    log_lines=None,
    override_rxpk=False,
):
    prune_replay_cache()
    token = secrets.token_urlsafe(16)
    REPLAY_CACHE[token] = {
        "ts": time.time(),
        "status": "running",
        "total": total,
        "sent": sent,
        "errors": errors,
        "host": host,
        "port": port,
        "delay_ms": delay_ms,
        "start_index": start_index,
        "current_index": start_index,
        "log_lines": list(log_lines or []),
        "override_rxpk": bool(override_rxpk),
    }
    return token


def get_replay_job(token):
    prune_replay_cache()
    return REPLAY_CACHE.get(token)


def update_replay_job(token, **updates):
    with REPLAY_LOCK:
        entry = REPLAY_CACHE.get(token)
        if not entry:
            return
        entry.update(updates)
        entry["ts"] = time.time()


def append_replay_log(token, log_line, sent=None, errors=None, status=None):
    with REPLAY_LOCK:
        entry = REPLAY_CACHE.get(token)
        if not entry:
            return
        entry["log_lines"].append(log_line)
        if sent is not None:
            entry["sent"] = sent
        if errors is not None:
            entry["errors"] = errors
        if status is not None:
            entry["status"] = status
        entry["ts"] = time.time()


def store_scan_result(parsed, gateways, devaddrs, filename, stored_log_id=""):
    prune_scan_cache()
    token = secrets.token_urlsafe(16)
    SCAN_CACHE[token] = {
        "parsed": parsed,
        "gateways": gateways,
        "devaddrs": devaddrs,
        "filename": filename,
        "stored_log_id": stored_log_id,
        "ts": time.time(),
    }
    return token


def get_scan_result(token):
    prune_scan_cache()
    entry = SCAN_CACHE.get(token)
    if not entry:
        return None
    return entry["parsed"], entry["gateways"], entry["devaddrs"], entry["filename"], entry.get("stored_log_id", "")


def store_decode_result(rows):
    prune_decode_cache()
    token = secrets.token_urlsafe(16)
    DECODE_CACHE[token] = {"rows": rows, "ts": time.time()}
    return token


def get_decode_result(token):
    prune_decode_cache()
    entry = DECODE_CACHE.get(token)
    if not entry:
        return None
    return entry["rows"]


def format_list(label, items, limit=10):
    if not items:
        return f"{label}: none"
    if len(items) <= limit:
        return f"{label}: {', '.join(items)}"
    remaining = len(items) - limit
    preview = ", ".join(items[:limit])
    return f"{label}: {preview} (+{remaining} more)"


JS_DECODER_RUNNER = r"""
const fs = require("fs");
const vm = require("vm");

const path = process.argv[1];
const fport = parseInt(process.argv[2], 10) || 0;
const b64 = process.argv[3] || "";
const buf = Buffer.from(b64, "base64");
const bytes = Array.from(buf.values());

const code = fs.readFileSync(path, "utf8");
const sandbox = { console: console };
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

let result;
if (typeof sandbox.Decoder === "function") {
  result = { data: sandbox.Decoder(bytes, fport) };
} else if (typeof sandbox.decodeUplink === "function") {
  result = sandbox.decodeUplink({ bytes: bytes, fPort: fport });
} else if (typeof sandbox.decode === "function") {
  result = sandbox.decode(bytes, fport);
} else {
  throw new Error("Decoder file must export decodeUplink(), Decoder(), or decode().");
}

process.stdout.write(JSON.stringify(result === undefined ? null : result));
"""


def list_decoders():
    ensure_data_dirs()
    decoders = [{"id": "raw", "label": "Raw payload (hex)", "source": "builtin"}]
    for filename in sorted(os.listdir(BUILTIN_DECODER_DIR)):
        if filename.lower().endswith(".js"):
            decoder_id = f"builtin:{filename}"
            decoders.append({"id": decoder_id, "label": filename, "source": "builtin"})
    if DECODER_FILE_EXECUTION_ENABLED:
        for filename in sorted(os.listdir(DECODER_DIR)):
            if filename.lower().endswith(".js"):
                decoder_id = f"file:{filename}"
                decoders.append({"id": decoder_id, "label": filename, "source": "upload"})
    return decoders


def load_decoder(decoder_id):
    if decoder_id == "raw":
        def decode(payload, fport, devaddr, rxpk):
            return {"payload_hex": payload.hex().upper(), "fport": fport}

        return decode

    def load_js_decoder(path):
        if not os.path.exists(path):
            raise ValueError("Decoder file not found.")

        def decode(payload, fport, devaddr, rxpk):
            if fport is None:
                fport_value = 0
            else:
                fport_value = int(fport)
            b64_payload = base64.b64encode(payload).decode("ascii")
            try:
                result = subprocess.run(
                    ["node", "-e", JS_DECODER_RUNNER, path, str(fport_value), b64_payload],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except FileNotFoundError as exc:
                raise ValueError("Node.js is required to run JS decoders.") from exc
            except subprocess.CalledProcessError as exc:
                err = exc.stderr.strip() or "Unknown decoder error."
                raise ValueError(err) from exc
            output = result.stdout.strip()
            if not output:
                return None
            return json.loads(output)

        return decode

    if decoder_id.startswith("builtin:"):
        filename = decoder_id.split("builtin:", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        path = os.path.join(BUILTIN_DECODER_DIR, filename)
        return load_js_decoder(path)

    if decoder_id.startswith("file:"):
        if not DECODER_FILE_EXECUTION_ENABLED:
            raise ValueError("Uploaded decoders are disabled.")
        filename = decoder_id.split("file:", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        path = os.path.join(DECODER_DIR, filename)
        return load_js_decoder(path)

    raise ValueError("Unknown decoder selection.")


def resolve_decoder_path(decoder_id):
    if decoder_id.startswith("builtin:"):
        filename = decoder_id.split(":", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        return os.path.join(BUILTIN_DECODER_DIR, filename)
    if decoder_id.startswith("file:"):
        if not DECODER_FILE_EXECUTION_ENABLED:
            raise ValueError("Uploaded decoders are disabled.")
        filename = decoder_id.split(":", 1)[1]
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Invalid decoder selection.")
        return os.path.join(DECODER_DIR, filename)
    raise ValueError("Unknown decoder selection.")


def nav_context(active_page, logo_url):
    csrf_token = get_csrf_token()
    context = {
        "active_page": active_page,
        "start_url": url_for("index"),
        "devices_url": url_for("device_keys"),
        "users_url": url_for("users_page"),
        "files_url": url_for("files_page"),
        "decoders_url": url_for("decoders_page"),
        "integrations_url": url_for("integrations_page"),
        "about_url": url_for("about_page"),
        "logout_url": url_for("logout"),
        "show_menu": current_user.is_authenticated,
        "csrf_token": csrf_token,
    }
    nav_html = render_template_string(NAV_HTML, logo_url=logo_url, **context)
    return {**context, "nav_html": nav_html}


def render_main_page(
    result_lines=None,
    result_class="",
    log_lines=None,
    form_values=None,
    scan_token="",
    selected_filename="",
    stored_logs=None,
    selected_stored_id="",
):
    values = {
        "host": "127.0.0.1",
        "port": "1700",
        "delay_ms": "500",
    }
    if form_values:
        values["host"] = form_values.get("host", values["host"])
        values["port"] = form_values.get("port", values["port"])
        values["delay_ms"] = form_values.get("delay_ms", values["delay_ms"])
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        replay_url=url_for("replay"),
        replay_page_url=url_for("replay"),
        scan_url=url_for("scan"),
        decode_url=url_for("decode"),
        form_values=values,
        result_lines=result_lines or [],
        result_class=result_class,
        log_lines=log_lines or [],
        scan_token=scan_token,
        selected_filename=selected_filename,
        stored_logs=stored_logs or [],
        selected_stored_id=selected_stored_id,
        **nav_context("start", logo_url),
    )


def render_replay_page(
    form_values=None,
    scan_token="",
    selected_filename="",
    summary_lines=None,
    summary_class="",
    result_lines=None,
    result_class="",
    log_lines=None,
    replay_token="",
    replay_total=0,
    replay_status="",
    back_url="",
):
    values = {
        "host": "127.0.0.1",
        "port": "1700",
        "delay_ms": "500",
        "override_rxpk": False,
    }
    if form_values:
        values["host"] = form_values.get("host", values["host"])
        values["port"] = form_values.get("port", values["port"])
        values["delay_ms"] = form_values.get("delay_ms", values["delay_ms"])
        override_raw = form_values.get("override_rxpk", values["override_rxpk"])
        if isinstance(override_raw, str):
            values["override_rxpk"] = override_raw.strip().lower() in ("1", "true", "yes", "on")
        else:
            values["override_rxpk"] = bool(override_raw)
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        REPLAY_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        replay_url=url_for("replay"),
        replay_status_url=url_for("replay_status"),
        replay_stop_url=url_for("replay_stop"),
        replay_resume_url=url_for("replay_resume"),
        form_values=values,
        scan_token=scan_token,
        selected_filename=selected_filename,
        summary_lines=summary_lines or [],
        summary_class=summary_class,
        result_lines=result_lines or [],
        result_class=result_class,
        log_lines=log_lines or [],
        replay_token=replay_token,
        replay_total=replay_total,
        replay_status=replay_status,
        back_url=back_url or url_for("index"),
        **nav_context("start", logo_url),
    )


def render_simple_page(title, subtitle, body_html, active_page, page_title=None):
    logo_url = url_for("static", filename="company_logo.png")
    back_url = resolve_back_url(url_for("index"))
    title_icons = {
        "start": "home",
        "devices": "memory",
        "users": "group",
        "files": "folder",
        "decoders": "code",
        "integrations": "hub",
        "about": "info",
    }
    title_icon = title_icons.get(active_page)
    return render_template_string(
        SIMPLE_PAGE_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        title=title,
        title_icon=title_icon,
        subtitle=subtitle,
        body_html=body_html,
        page_title=page_title or title,
        back_url=back_url,
        **nav_context(active_page, logo_url),
    )


def render_generator_page(
    form_values=None,
    error_message="",
    generated_entry=None,
    generated_scan_token="",
):
    values = form_values if form_values is not None else get_generator_form_values()
    logo_url = url_for("static", filename="company_logo.png")
    download_url = ""
    replay_url = ""
    decode_url = ""
    filename = ""
    if generated_entry:
        download_url = url_for("download_log_file", log_id=generated_entry["id"])
        replay_url = url_for("replay")
        decode_url = url_for("decode")
        filename = generated_entry.get("filename", "")
    return render_template_string(
        GENERATOR_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        generator_url=url_for("generate_log_page"),
        form_values=values,
        error_message=error_message,
        generated_entry=generated_entry,
        generated_download_url=download_url,
        generated_scan_token=generated_scan_token,
        generated_filename=filename,
        replay_url=replay_url,
        decode_url=decode_url,
        freq_options=EU868_FREQ_OPTIONS,
        datarate_options=EU868_DATARATE_OPTIONS,
        coding_rate_options=EU868_CODING_RATE_OPTIONS,
        payload_examples=PAYLOAD_EXAMPLES,
        **nav_context("files", logo_url),
    )


def render_decode_page(
    scan_token,
    devaddrs,
    credentials,
    summary_lines=None,
    result_class="success",
    missing_keys=None,
    decoders=None,
    selected_decoder="raw",
    decode_results=None,
    decode_columns=None,
    selected_filename="",
    export_token="",
    back_url="",
):
    export_csv_url = url_for("export_results", fmt="csv", token=export_token) if export_token else ""
    export_json_url = url_for("export_results", fmt="json", token=export_token) if export_token else ""
    analyze_url = url_for("analyze_results", token=export_token, scan_token=scan_token) if export_token else ""
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        DECODE_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        decode_url=url_for("decode"),
        decode_progress_url=url_for("decode_progress"),
        keys_url=url_for("device_keys"),
        scan_token=scan_token,
        summary_lines=summary_lines or [],
        result_class=result_class,
        devaddrs=devaddrs,
        credentials=credentials,
        missing_keys=missing_keys or [],
        decoders=decoders or [],
        selected_decoder=selected_decoder,
        decode_results=decode_results,
        decode_columns=decode_columns or [],
        selected_filename=selected_filename,
        export_csv_url=export_csv_url,
        export_json_url=export_json_url,
        analyze_url=analyze_url,
        export_token=export_token,
        back_url=back_url or url_for("index"),
        **nav_context("decoders", logo_url),
    )


def render_device_keys_page(
    credentials,
    summary_lines=None,
    result_class="success",
    scan_token="",
    scan_summary_lines=None,
    scan_filename="",
    back_url="",
):
    known_devaddrs = sorted(credentials.keys())
    decode_url = url_for("decode")
    if scan_token:
        decode_url = f"{decode_url}?scan_token={scan_token}"
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        DEVICE_KEYS_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        decode_url=decode_url,
        keys_url=url_for("device_keys"),
        summary_lines=summary_lines or [],
        result_class=result_class,
        credentials=credentials,
        known_devaddrs=known_devaddrs,
        scan_token=scan_token,
        scan_summary_lines=scan_summary_lines or [],
        scan_filename=scan_filename,
        back_url=back_url or url_for("index"),
        **nav_context("devices", logo_url),
    )


def is_safe_redirect(target):
    if not target:
        return False
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme or parsed.netloc:
        return False
    return True


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        config = get_auth_config()
        if config.get("must_change"):
            return redirect(url_for("change_password"))
        return redirect(url_for("index"))
    error_message = ""
    next_url = request.args.get("next") or request.form.get("next") or ""
    config = get_auth_config()
    configured = bool(config.get("users"))
    if request.method == "POST":
        if not configured:
            error_message = "Authentication is not configured."
            audit_log("login_failed", {"username": request.form.get("username", "").strip(), "reason": "not_configured"})
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if verify_credentials(username, password):
                login_user(AppUser(username))
                audit_log("login_success", {"username": username})
                user_entry = config.get("users", {}).get(username, {})
                if user_entry.get("must_change"):
                    return redirect(url_for("change_password"))
                if is_safe_redirect(next_url):
                    return redirect(next_url)
                return redirect(url_for("index"))
            audit_log("login_failed", {"username": username, "reason": "invalid_credentials"})
            error_message = "Invalid username or password."
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        LOGIN_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        login_url=url_for("login"),
        error_message=error_message,
        configured=configured,
        next_url=next_url,
        **nav_context("start", logo_url),
    )


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    error_message = ""
    success_message = ""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not verify_credentials(current_user.id, current_password):
            error_message = "Current password is incorrect."
        elif not new_password:
            error_message = "New password is required."
        elif new_password != confirm_password:
            error_message = "New passwords do not match."
        else:
            set_auth_password(current_user.id, new_password)
            audit_log("password_changed", {"username": current_user.id})
            return redirect(url_for("index"))
    logo_url = url_for("static", filename="company_logo.png")
    return render_template_string(
        CHANGE_PASSWORD_HTML,
        style_block=STYLE_BLOCK,
        script_block=SCRIPT_BLOCK,
        logo_url=logo_url,
        favicon_url=url_for("static", filename="favicon.ico"),
        change_password_url=url_for("change_password"),
        error_message=error_message,
        success_message=success_message,
        **nav_context("start", logo_url),
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit_log("logout", {"username": current_user.id})
    logout_user()
    return redirect(url_for("login"))


@app.route("/users", methods=["GET", "POST"])
@login_required
def users_page():
    users = get_users()
    summary_lines = []
    result_class = "success"
    action = request.form.get("action", "").strip()
    csrf_input = get_csrf_input()

    if action == "add_user":
        username = request.form.get("new_username", "").strip()
        password = request.form.get("new_password", "")
        if not username or not password:
            summary_lines = ["Username and password are required."]
            result_class = "error"
        elif username in users:
            summary_lines = [f"User {username} already exists."]
            result_class = "error"
        else:
            users[username] = {
                "password_hash": generate_password_hash(password),
                "must_change": True,
                "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
            save_users(users)
            audit_log("user_created", {"username": username})
            summary_lines = [f"User {username} created."]

    if action == "update_user":
        username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "")
        if username not in users:
            summary_lines = [f"User {username} not found."]
            result_class = "error"
        elif username == "admin" and current_user.id != "admin":
            summary_lines = ["Only admin can reset the admin password."]
            result_class = "error"
        elif not new_password:
            summary_lines = ["New password is required."]
            result_class = "error"
        else:
            users[username]["password_hash"] = generate_password_hash(new_password)
            users[username]["must_change"] = True
            save_users(users)
            audit_log("user_password_reset", {"username": username})
            summary_lines = [f"Password reset for {username}."]

    if action == "delete_user":
        username = request.form.get("username", "").strip()
        if username == "admin":
            summary_lines = ["The admin account cannot be removed."]
            result_class = "error"
        elif username == current_user.id:
            summary_lines = ["You cannot remove your own account."]
            result_class = "error"
        elif username not in users:
            summary_lines = [f"User {username} not found."]
            result_class = "error"
        else:
            users.pop(username, None)
            save_users(users)
            audit_log("user_deleted", {"username": username})
            summary_lines = [f"User {username} removed."]

    sorted_users = sorted(users.items(), key=lambda item: item[0].lower())
    user_rows = []
    for username, entry in sorted_users:
        must_change = "Yes" if entry.get("must_change") else "No"
        can_edit_admin = current_user.id == "admin"
        reset_disabled = username == "admin" and not can_edit_admin
        show_remove = username != "admin"
        remove_html = ""
        if show_remove:
            remove_html = (
                f"<div class=\"remove-cell\">"
                f"<form method=\"POST\" action=\"{url_for('users_page')}\">"
                f"{csrf_input}"
                f"<input type=\"hidden\" name=\"action\" value=\"delete_user\">"
                f"<input type=\"hidden\" name=\"username\" value=\"{html.escape(username)}\">"
                f"<button type=\"submit\" class=\"danger-button danger-text\">"
                f"<span class=\"material-icons\" aria-hidden=\"true\">delete</span>"
                f"<span>Remove</span></button>"
                f"</form>"
                f"</div>"
            )
        user_rows.append(
            f"<div class=\"device-row\">"
            f"<div class=\"key-grid user-grid\">"
            f"<div>"
            f"<label>Username</label>"
            f"<div class=\"hint user-name\" data-user-name=\"{html.escape(username)}\">{html.escape(username)}</div>"
            f"</div>"
            f"<div>"
            f"<label>Must change password</label>"
            f"<div class=\"hint\">{must_change}</div>"
            f"</div>"
            f"<div>"
            f"<div class=\"users-password-row\">"
            f"<button type=\"button\" class=\"secondary-button\" data-password-reset=\"{html.escape(username)}\" "
            f"{'disabled' if reset_disabled else ''}>Change password</button>"
            f"</div>"
            f"</div>"
            f"{remove_html}"
            f"</div>"
            f"</div>"
        )
    rows_html = "".join(user_rows) if user_rows else "<div class=\"hint\">No users found.</div>"

    result_html = ""
    if summary_lines:
        summary_items = "".join(f"<div>{html.escape(line)}</div>" for line in summary_lines)
        result_html = f"<div class=\"result {result_class}\">{summary_items}</div>"

    body_html = f"""
      {result_html}
      <div class=\"field-group\">
        <div class=\"field-header\">
          <label>Users</label>
        </div>
        <div class=\"hint\">Reset passwords or remove accounts. New users will be asked to change their password on first login.</div>
        <div class=\"device-rows\">
          {rows_html}
        </div>
      </div>
      <div class=\"section-divider\"></div>
      <form method=\"POST\" action=\"{url_for('users_page')}\">
        {csrf_input}
        <input type=\"hidden\" name=\"action\" value=\"add_user\">
        <div class=\"field-group\">
          <div class=\"field-header\">
            <label>Add user</label>
          </div>
          <div class=\"key-grid user-add-grid\">
            <div>
              <label for=\"new_username\">Username</label>
              <input id=\"new_username\" name=\"new_username\" type=\"text\" required>
            </div>
            <div>
              <label for=\"new_password\">Temporary password</label>
              <div class=\"field-controls\">
                <input id=\"new_password\" name=\"new_password\" type=\"text\" data-temp-password required>
                <div class=\"field-tools\">
                  <button type=\"button\" class=\"icon-button\" data-temp-generate title=\"Generate password\"><span class="material-icons" aria-hidden="true">autorenew</span></button>
                  <button type=\"button\" class=\"icon-button\" data-temp-copy title=\"Copy password\"><span class="material-icons" aria-hidden="true">content_copy</span></button>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class=\"form-actions\">
          <button type=\"submit\" class=\"primary-button\"><span class=\"material-icons\" aria-hidden=\"true\">person_add</span>Add user</button>
        </div>
      </form>
      <div class=\"modal-overlay\" data-password-modal hidden>
        <div class=\"modal-card\">
          <h2>Change password</h2>
          <div class=\"hint\">Set a new password for <strong data-password-user></strong>.</div>
          <form method=\"POST\" action=\"{url_for('users_page')}\" data-password-form>
            {csrf_input}
            <input type=\"hidden\" name=\"action\" value=\"update_user\">
            <input type=\"hidden\" name=\"username\" value=\"\" data-password-username>
            <div>
              <label for=\"modal_password\">New password</label>
              <div class=\"field-controls\">
                <input id=\"modal_password\" name=\"new_password\" type=\"text\" data-password-input required>
                <div class=\"field-tools\">
                  <button type=\"button\" class=\"icon-button\" data-password-generate title=\"Generate password\"><span class="material-icons" aria-hidden="true">autorenew</span></button>
                  <button type=\"button\" class=\"icon-button\" data-password-copy title=\"Copy password\"><span class="material-icons" aria-hidden="true">content_copy</span></button>
                </div>
              </div>
            </div>
            <div class=\"modal-actions\">
              <button type=\"submit\">Update password</button>
              <button type=\"button\" class=\"secondary-button\" data-password-close><span class=\"material-icons\" aria-hidden=\"true\">close</span>Close</button>
            </div>
          </form>
        </div>
      </div>
    """
    return render_simple_page(
        title="Users",
        subtitle="Manage access for this app.",
        body_html=body_html,
        active_page="users",
    )


@app.route("/", methods=["GET"])
@login_required
def index():
    stored_logs = list_stored_logs()
    return render_main_page(stored_logs=stored_logs)


@app.route("/keys", methods=["GET"])
@login_required
def keys_redirect():
    return redirect(url_for("device_keys"))


@app.route("/files", methods=["GET"])
@login_required
def files_page():
    stored_logs = list_stored_logs()
    csrf_input = get_csrf_input()
    saved_by_log = {}
    for entry in list_saved_decode_results():
        log_id = entry.get("log_id") or ""
        if not log_id:
            continue
        saved_by_log.setdefault(log_id, []).append(entry)
    if stored_logs:
        items = []
        for log in stored_logs:
            log_id = html.escape(log["id"])
            filename = html.escape(log["filename"])
            uploaded_at = html.escape(log["uploaded_at"])
            view_url = url_for("view_log_file", log_id=log["id"])
            download_url = url_for("download_log_file", log_id=log["id"])
            decode_url = url_for("start_decode_from_file", log_id=log["id"])
            replay_url = url_for("start_replay_from_file", log_id=log["id"])
            saved_entries = saved_by_log.get(log["id"], [])
            saved_html = ""
            if saved_entries:
                saved_items = []
                for saved in saved_entries:
                    created_at = html.escape(saved.get("created_at", ""))
                    decoder_id = html.escape(saved.get("decoder_id", ""))
                    decoder_meta = f"<span class=\"decoder-meta\">{decoder_id}</span>" if decoder_id else ""
                    analyze_url = url_for("analyze_results", saved_id=saved.get("id", ""))
                    export_csv_url = url_for("export_saved_results", fmt="csv", saved_id=saved.get("id", ""))
                    export_json_url = url_for("export_saved_results", fmt="json", saved_id=saved.get("id", ""))
                    saved_items.append(
                        f"<div class=\"saved-entry\">"
                        f"<span class=\"saved-label\">Saved results ({created_at})</span>"
                        f"<a class=\"secondary-button\" href=\"{analyze_url}\"><span class=\"material-icons\" aria-hidden=\"true\">analytics</span>Analyze</a>"
                        f"<a class=\"secondary-button\" href=\"{export_csv_url}\"><span class=\"material-icons\" aria-hidden=\"true\">file_download</span>CSV</a>"
                        f"<a class=\"secondary-button\" href=\"{export_json_url}\"><span class=\"material-icons\" aria-hidden=\"true\">file_download</span>JSON</a>"
                        f"{decoder_meta}"
                        f"</div>"
                    )
                saved_html = f"<div class=\"saved-results\">{''.join(saved_items)}</div>"
            items.append(
                f"<details class=\"file-entry\" data-file-item "
                f"data-file-name=\"{filename.lower()}\" data-file-date=\"{uploaded_at}\">"
                f"<summary>"
                f"<div class=\"file-summary\">"
                f"<span class=\"decoder-link\">{filename}</span>"
                f"<span class=\"file-meta\">{uploaded_at}</span>"
                f"</div>"
                f"<span class=\"file-meta\">Actions</span>"
                f"</summary>"
                f"<div class=\"file-body\">"
                f"<div class=\"file-actions\">"
                f"<a class=\"secondary-button\" href=\"{view_url}\"><span class=\"material-icons\" aria-hidden=\"true\">visibility</span>View</a>"
                f"<a class=\"secondary-button\" href=\"{download_url}\"><span class=\"material-icons\" aria-hidden=\"true\">download</span>Download</a>"
                f"<a class=\"secondary-button\" href=\"{decode_url}\"><span class=\"material-icons\" aria-hidden=\"true\">lock_open</span>Decrypt &amp; decode</a>"
                f"<a class=\"secondary-button\" href=\"{url_for('start_scan_from_file', log_id=log['id'])}\"><span class=\"material-icons\" aria-hidden=\"true\">qr_code_scanner</span>Scan</a>"
                f"<a class=\"secondary-button\" href=\"{replay_url}\"><span class=\"material-icons\" aria-hidden=\"true\">play_arrow</span>Replay</a>"
                f"<button type=\"button\" class=\"danger-button danger-text\" "
                f"data-delete-file=\"{log_id}\" "
                f"title=\"Remove log file\" aria-label=\"Remove log file\"><span class=\"material-icons\" aria-hidden=\"true\">delete</span><span>Remove</span></button>"
                f"</div>"
                f"{saved_html}"
                f"</div>"
                f"</details>"
            )
        stored_html = f"<div class=\"file-list\" data-file-list>{''.join(items)}</div>"
    else:
        stored_html = "<div class=\"hint\">No stored log files yet.</div>"

    body_html = f"""
      <form method="POST" action="{url_for('delete_log_file')}" data-file-delete-form>
        {csrf_input}
        <input type="hidden" name="log_id" value="" data-file-delete-input>
      </form>
      <div class="field-group">
        <div class="field-header">
          <label>Stored log files</label>
        </div>
        <div class="hint">Review, download, and process previously uploaded logs.</div>
        <div class="file-controls">
          <div>
            <label for="file_search">Search files</label>
            <input id="file_search" type="text" placeholder="Search by filename..." data-file-search>
          </div>
          <div>
            <label for="file_sort">Sort by</label>
            <select id="file_sort" data-file-sort>
              <option value="date_desc">Newest first</option>
              <option value="date_asc">Oldest first</option>
              <option value="name_asc">Filename (A-Z)</option>
              <option value="name_desc">Filename (Z-A)</option>
            </select>
          </div>
        </div>
        {stored_html}
      </div>
      <div class="section-divider"></div>
      <div class="logfile-options">
        <div class="logfile-option">
          <h3>Upload a log file</h3>
          <div class="hint">Upload a new JSONL log and scan it right away.</div>
          <form method="POST" action="{url_for('scan')}" enctype="multipart/form-data" data-scan-url="{url_for('scan')}">
            {csrf_input}
            <input id="logfile" type="file" name="logfile" style="display: none;" aria-hidden="true">
            <input type="hidden" name="redirect_to" value="files">
            <div class="file-drop" data-file-drop>
              <div class="file-text">
                <strong>Click to choose or drag & drop</strong>
                <div class="file-selected" data-file-selected>No file selected</div>
              </div>
            </div>
          </form>
        </div>
        <div class="logfile-option">
          <h3>Generate a sample log file</h3>
          <div class="hint">Download a ready-made JSONL sample.</div>
          <div class="option-actions">
            <a class="secondary-button" href="{url_for('generate_log_page')}"><span class="material-icons" aria-hidden="true">auto_awesome</span>Generate sample</a>
          </div>
        </div>
      </div>
    """
    return render_simple_page(
        title="Files",
        subtitle="Review stored log files and generate samples.",
        body_html=body_html,
        active_page="files",
    )


@app.route("/decoders", methods=["GET", "POST"])
@login_required
def decoders_page():
    summary_lines = []
    result_class = "success"
    action = request.form.get("action", "").strip()
    csrf_input = get_csrf_input()
    uploads_enabled = DECODER_UPLOADS_ENABLED
    file_execution_enabled = DECODER_FILE_EXECUTION_ENABLED
    if request.method == "POST" and action == "upload_decoder":
        if not uploads_enabled:
            summary_lines = ["Decoder uploads are disabled."]
            result_class = "error"
        else:
            allowed, retry_after = check_rate_limit("decoder_upload", get_user_id())
            if not allowed:
                summary_lines = [f"Rate limit exceeded. Try again in {retry_after} seconds."]
                result_class = "error"
            else:
                decoder_file = request.files.get("decoder_file")
                if not decoder_file or not decoder_file.filename:
                    summary_lines = ["Please choose a decoder file to upload."]
                    result_class = "error"
                else:
                    filename = secure_filename(decoder_file.filename)
                    if not filename.lower().endswith(".js"):
                        summary_lines = ["Decoder file must be a .js file."]
                        result_class = "error"
                    else:
                        ensure_data_dirs()
                    path = os.path.join(DECODER_DIR, filename)
                    decoder_file.save(path)
                    summary_lines = [f"Decoder uploaded: {filename}"]
                    result_class = "success"
                    audit_log("decoder_uploaded", {"filename": filename})
    if request.method == "POST" and action == "delete_decoder":
        if not uploads_enabled:
            summary_lines = ["Decoder management is disabled."]
            result_class = "error"
        else:
            decoder_id = request.form.get("delete_decoder_id", "").strip()
            if not decoder_id:
                summary_lines = ["Select a decoder to remove."]
                result_class = "error"
            elif not decoder_id.startswith("file:"):
                summary_lines = ["Built-in decoders cannot be removed."]
                result_class = "error"
            else:
                try:
                    path = resolve_decoder_path(decoder_id)
                except ValueError as exc:
                    summary_lines = [str(exc)]
                    result_class = "error"
                else:
                    if os.path.exists(path):
                        os.remove(path)
                        summary_lines = ["Decoder removed."]
                        result_class = "success"
                        audit_log("decoder_deleted", {"decoder_id": decoder_id})
                    else:
                        summary_lines = ["Decoder file not found."]
                        result_class = "error"

    decoders = list_decoders()
    if decoders:
        items = []
        for decoder in decoders:
            label = html.escape(decoder["label"])
            source = html.escape(decoder["source"])
            decoder_id = html.escape(decoder["id"])
            view_url = url_for("view_decoder", decoder_id=decoder["id"])
            actions_html = ""
            if decoder["id"] == "raw":
                actions_html = ""
            else:
                delete_button = ""
                if decoder["id"].startswith("file:") and uploads_enabled:
                    delete_button = (
                        f"<button type=\"button\" class=\"danger-button danger-text\" "
                        f"data-delete-decoder=\"{decoder_id}\" "
                        f"title=\"Remove decoder\" aria-label=\"Remove decoder\">"
                        f"<span class=\"material-icons\" aria-hidden=\"true\">delete</span>"
                        f"<span>Remove</span></button>"
                    )
                actions_html = (
                    f"<div class=\"decoder-actions\">"
                    f"<a class=\"secondary-button\" href=\"{view_url}\">"
                    f"<span class=\"material-icons\" aria-hidden=\"true\">visibility</span>View</a>"
                    f"{delete_button}"
                    f"</div>"
                )
            if decoder["id"] == "raw":
                name_html = f"<span class=\"decoder-link\">{label}</span>"
            else:
                name_html = f"<a class=\"decoder-link\" href=\"{view_url}\">{label}</a>"
            items.append(
                f"<li class=\"decoder-item\">"
                f"<div>"
                f"{name_html}"
                f"<span class=\"decoder-meta\">({source})</span>"
                f"</div>"
                f"{actions_html}"
                f"</li>"
            )
        decoder_html = f"<ul class=\"decoder-list\">{''.join(items)}</ul>"
    else:
        decoder_html = "<div class=\"hint\">No decoders available yet.</div>"

    result_html = ""
    if summary_lines:
        summary_items = "".join(f"<div>{html.escape(line)}</div>" for line in summary_lines)
        result_html = f"<div class=\"result {result_class}\">{summary_items}</div>"

    decoder_notice = ""
    if not file_execution_enabled:
        decoder_notice = "<div class=\"hint\">Uploaded decoders are disabled for this deployment.</div>"
    upload_section = ""
    if uploads_enabled:
        upload_section = f"""
      <div class="section-divider"></div>
      <form method="POST" action="{url_for('decoders_page')}" enctype="multipart/form-data">
        {csrf_input}
        <input type="hidden" name="action" value="upload_decoder">
        <div class="field-group">
          <div class="field-header">
            <label for="decoder_file">Add a decoder</label>
          </div>
          <input id="decoder_file" name="decoder_file" type="file" accept=".js">
          <div class="hint">JS decoders should define <code>Decoder(bytes, port)</code> or <code>decodeUplink({{ bytes, fPort }})</code>.</div>
        </div>
        <div class="form-actions">
          <button type="submit" class="primary-button"><span class="material-icons" aria-hidden="true">upload</span>Upload decoder</button>
        </div>
      </form>
        """
    else:
        upload_section = "<div class=\"section-divider\"></div><div class=\"hint\">Decoder uploads are disabled for this deployment.</div>"

    body_html = f"""
      {result_html}
      <form method="POST" action="{url_for('decoders_page')}" data-decoder-delete-form>
        {csrf_input}
        <input type="hidden" name="action" value="delete_decoder">
        <input type="hidden" name="delete_decoder_id" value="" data-decoder-delete-input>
      </form>
      <div class="field-group">
        <div class="field-header">
          <label>Available decoders</label>
        </div>
        <div class="hint">Click a decoder to review its JavaScript.</div>
        {decoder_notice}
        {decoder_html}
      </div>
      {upload_section}
    """
    return render_simple_page(
        title="Decoders",
        subtitle="Upload and select payload decoders for log files.",
        body_html=body_html,
        active_page="decoders",
    )


@app.route("/integrations", methods=["GET"])
@login_required
def integrations_page():
    body_html = f"""
      <div class="logfile-options">
        <div class="logfile-option integration-block">
          <h3>EarthRanger (HTTP)</h3>
          <div class="hint">Send decoded uplinks to EarthRanger via HTTP integration.</div>
          <div class="option-actions">
            <button type="button" class="secondary-button"><span class="material-icons" aria-hidden="true">add</span>Add integration</button>
            <button type="button" class="secondary-button"><span class="material-icons" aria-hidden="true">settings</span>Manage</button>
          </div>
        </div>
        <div class="logfile-option integration-block">
          <h3>InfluxDB</h3>
          <div class="hint">Stream decoded uplinks into an InfluxDB bucket.</div>
          <div class="option-actions">
            <button type="button" class="secondary-button"><span class="material-icons" aria-hidden="true">add</span>Add integration</button>
            <button type="button" class="secondary-button"><span class="material-icons" aria-hidden="true">settings</span>Manage</button>
          </div>
        </div>
        <div class="logfile-option integration-block">
          <h3>MQTT</h3>
          <div class="hint">Publish decoded uplinks to an MQTT broker.</div>
          <div class="option-actions">
            <button type="button" class="secondary-button"><span class="material-icons" aria-hidden="true">add</span>Add integration</button>
            <button type="button" class="secondary-button"><span class="material-icons" aria-hidden="true">settings</span>Manage</button>
          </div>
        </div>
      </div>
    """
    return render_simple_page(
        title="Integrations",
        subtitle="Connect log playback to external tools and services.",
        body_html=body_html,
        active_page="integrations",
    )


@app.route("/decoders/view", methods=["GET"])
@login_required
def view_decoder():
    decoder_id = request.args.get("decoder_id", "").strip()
    if not decoder_id:
        return render_simple_page(
            title="Decoder Viewer",
            subtitle="Select a decoder to view its source.",
            body_html="<div class=\"hint\">No decoder selected.</div>",
            active_page="decoders",
            page_title="Decoder Viewer",
        )
    try:
        path = resolve_decoder_path(decoder_id)
    except ValueError as exc:
        return render_simple_page(
            title="Decoder Viewer",
            subtitle="Unable to load decoder.",
            body_html=f"<div class=\"result error\">{html.escape(str(exc))}</div>",
            active_page="decoders",
            page_title="Decoder Viewer",
        )
    if not os.path.exists(path):
        return render_simple_page(
            title="Decoder Viewer",
            subtitle="Decoder not found.",
            body_html="<div class=\"result error\">Decoder file not found.</div>",
            active_page="decoders",
            page_title="Decoder Viewer",
        )
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    body_html = f"""
      <div class="field-group">
        <div class="field-header">
          <label>{html.escape(os.path.basename(path))}</label>
        </div>
        <pre class="code-block">{html.escape(content)}</pre>
      </div>
      <div class="form-actions">
        <a class="secondary-button" href="{url_for('decoders_page')}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back to Decoders</a>
      </div>
    """
    return render_simple_page(
        title="Decoder Viewer",
        subtitle="Review the decoder JavaScript before using it.",
        body_html=body_html,
        active_page="decoders",
        page_title="Decoder Viewer",
    )


@app.route("/files/view", methods=["GET"])
@login_required
def view_log_file():
    log_id = request.args.get("log_id", "").strip()
    entry = get_stored_log_entry(log_id) if log_id else None
    if not entry:
        return render_simple_page(
            title="Log File Viewer",
            subtitle="Log file not found.",
            body_html="<div class=\"result error\">Log file not found.</div>",
            active_page="files",
            page_title="Log File Viewer",
        )
    audit_log("log_viewed", {"log_id": entry.get("id"), "filename": entry.get("filename")})
    path = entry["path"]
    max_bytes = 200000
    with open(path, "rb") as handle:
        content_bytes = handle.read(max_bytes + 1)
    truncated = len(content_bytes) > max_bytes
    content_bytes = content_bytes[:max_bytes]
    content = content_bytes.decode("utf-8", errors="replace")
    note = ""
    if truncated:
        note = "<div class=\"hint\">Preview truncated to 200 KB.</div>"
    body_html = f"""
      <div class="field-group">
        <div class="field-header">
          <label>{html.escape(entry["filename"])}</label>
        </div>
        {note}
        <pre class="code-block">{html.escape(content)}</pre>
      </div>
      <div class="form-actions">
        <a class="secondary-button" href="{url_for('files_page')}"><span class="material-icons" aria-hidden="true">arrow_back</span>Back to Files</a>
      </div>
    """
    return render_simple_page(
        title="Log File Viewer",
        subtitle="Review the stored log file content.",
        body_html=body_html,
        active_page="files",
        page_title="Log File Viewer",
    )


@app.route("/files/download", methods=["GET"])
@login_required
def download_log_file():
    log_id = request.args.get("log_id", "").strip()
    entry = get_stored_log_entry(log_id) if log_id else None
    if not entry or not os.path.exists(entry["path"]):
        return "Log file not found.", 404
    audit_log("log_downloaded", {"log_id": entry.get("id"), "filename": entry.get("filename")})
    return send_file(entry["path"], as_attachment=True, download_name=entry["filename"])


@app.route("/files/delete", methods=["POST"])
@login_required
def delete_log_file():
    log_id = request.form.get("log_id", "").strip()
    if log_id:
        removed = delete_stored_log(log_id)
        if removed:
            audit_log("log_deleted", {"log_id": log_id})
    return redirect(url_for("files_page"))


@app.route("/files/decode", methods=["GET"])
@login_required
def start_decode_from_file():
    log_id = request.args.get("log_id", "").strip()
    try:
        scan_token, _entry = scan_stored_log(log_id)
    except ValueError as exc:
        body_html = f"<div class=\"result error\">{html.escape(str(exc))}</div>"
        return render_simple_page(
            title="Files",
            subtitle="Review stored log files and generate samples.",
            body_html=body_html,
            active_page="files",
            page_title="Files",
        )
    audit_log("log_scanned", {"scan_token": scan_token, "log_id": log_id})
    return redirect(url_for("decode", scan_token=scan_token))


@app.route("/files/replay", methods=["GET"])
@login_required
def start_replay_from_file():
    log_id = request.args.get("log_id", "").strip()
    try:
        scan_token, _entry = scan_stored_log(log_id)
    except ValueError as exc:
        body_html = f"<div class=\"result error\">{html.escape(str(exc))}</div>"
        return render_simple_page(
            title="Files",
            subtitle="Review stored log files and generate samples.",
            body_html=body_html,
            active_page="files",
            page_title="Files",
        )
    audit_log("log_scanned", {"scan_token": scan_token, "log_id": log_id})
    return redirect(url_for("replay", scan_token=scan_token))


def run_replay_job(token, parsed, host, port, delay_ms, start_index=0, sent=0, errors=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total = len(parsed)

    try:
        for idx, rec in enumerate(parsed[start_index:], start=start_index + 1):
            entry = get_replay_job(token)
            if not entry or entry.get("status") != "running":
                break
            gateway_eui = rec["gateway_eui"]
            rxpk = rec["rxpk"]
            if entry.get("override_rxpk"):
                # Copy so we do not mutate cached scan data.
                rxpk = {**rxpk, **REPLAY_RXPK_OVERRIDES}
            send_attempted = False

            try:
                packet = build_push_data(gateway_eui, rxpk)
            except Exception as exc:
                errors += 1
                try:
                    rxpk_serialized = json.dumps(rxpk)
                except Exception:
                    rxpk_serialized = str(rxpk) if rxpk is not None else ""
                rxpk_preview = rxpk_serialized[:100] + "..." if len(rxpk_serialized) > 100 else rxpk_serialized
                try:
                    fcnt = parse_uplink(rxpk)["fcnt"]
                except Exception:
                    fcnt = ""
                append_replay_log(
                    token,
                    {
                        "index": idx,
                        "status": "Error",
                        "send_time_ms": "",
                        "gateway": gateway_eui,
                        "fcnt": fcnt,
                        "freq": rxpk.get("freq"),
                        "size": rxpk.get("size"),
                        "message": f"Build error: {exc} -- {rxpk_preview}",
                        "css": "err",
                    },
                    sent=sent,
                    errors=errors,
                )
                update_replay_job(token, current_index=idx, sent=sent, errors=errors)
                continue

            try:
                sock.sendto(packet, (host, port))
                send_attempted = True
                sent += 1
                send_time_ms = int(time.time() * 1000)
                try:
                    fcnt = parse_uplink(rxpk)["fcnt"]
                except Exception:
                    fcnt = ""
                freq = rxpk.get("freq", "?")
                size = rxpk.get("size", len(packet))
                datr = rxpk.get("datr", "?")
                rssi = rxpk.get("rssi", "?")
                lsnr = rxpk.get("lsnr", "?")
                time_str = rxpk.get("time", "?")
                payload = rxpk.get("data", "")
                payload_preview = (payload[:60] + "...") if payload and len(payload) > 60 else payload or "n/a"
                append_replay_log(
                    token,
                    {
                        "index": idx,
                        "status": "Sent",
                        "send_time_ms": send_time_ms,
                        "gateway": gateway_eui,
                        "fcnt": fcnt,
                        "freq": freq,
                        "size": size,
                        "message": (
                            f"{time_str} datr={datr}, rssi={rssi} dBm, lsnr={lsnr} dB, "
                            f"data={payload_preview}"
                        ),
                        "css": "ok",
                    },
                    sent=sent,
                    errors=errors,
                )
            except Exception as exc:
                send_attempted = True
                errors += 1
                send_time_ms = int(time.time() * 1000)
                try:
                    rxpk_serialized = json.dumps(rxpk)
                except Exception:
                    rxpk_serialized = str(rxpk) if rxpk is not None else ""
                rxpk_preview = rxpk_serialized[:100] + "..." if len(rxpk_serialized) > 100 else rxpk_serialized
                try:
                    fcnt = parse_uplink(rxpk)["fcnt"]
                except Exception:
                    fcnt = ""
                append_replay_log(
                    token,
                    {
                        "index": idx,
                        "status": "Error",
                        "send_time_ms": send_time_ms,
                        "gateway": gateway_eui,
                        "fcnt": fcnt,
                        "freq": rxpk.get("freq"),
                        "size": rxpk.get("size"),
                        "message": f"Send error: {exc} -- {rxpk_preview}",
                        "css": "err",
                    },
                    sent=sent,
                    errors=errors,
                )

            if send_attempted and delay_ms > 0 and idx < total:
                time.sleep(delay_ms / 1000.0)
            update_replay_job(token, current_index=idx, sent=sent, errors=errors)
    finally:
        sock.close()
        entry = get_replay_job(token)
        status = entry.get("status") if entry else "done"
        if status == "running":
            status = "done"
        update_replay_job(token, status=status, sent=sent, errors=errors)


@app.route("/files/scan", methods=["GET"])
@login_required
def start_scan_from_file():
    log_id = request.args.get("log_id", "").strip()
    try:
        scan_token, _entry = scan_stored_log(log_id)
    except ValueError as exc:
        body_html = f"<div class=\"result error\">{html.escape(str(exc))}</div>"
        return render_simple_page(
            title="Files",
            subtitle="Review stored log files and generate samples.",
            body_html=body_html,
            active_page="files",
            page_title="Files",
        )
    audit_log("log_scanned", {"scan_token": scan_token, "log_id": log_id})
    return redirect(url_for("device_keys", scan_token=scan_token, show_scan="1"))


@app.route("/about", methods=["GET"])
@login_required
def about_page():
    logo_url = url_for("static", filename="company_logo.png")
    body_html = f"""
      <div class="logfile-options">
        <div class="logfile-option">
          <h3>About Smart Parks</h3>
          <div style="display: flex; align-items: center; gap: 0.8rem; margin: 0.6rem 0;">
            <img src="{logo_url}" alt="Smart Parks logo" style="width: 52px; height: auto;">
            <div class="hint">Protect Wildlife with Passion and Technology.</div>
          </div>
          <div class="hint">Smart Parks is a conservation technology organization focused on protecting wildlife and empowering rangers with resilient field tools.</div>
          <div class="hint">Their solutions combine on-animal sensors, ranger communications, and real-time monitoring to support anti-poaching and animal welfare across protected areas.</div>
          <div class="option-actions">
            <a class="secondary-button" href="https://www.smartparks.org" target="_blank" rel="noopener"><span class="material-icons" aria-hidden="true">open_in_new</span>www.smartparks.org</a>
          </div>
        </div>
        <div class="logfile-option">
          <h3>About the App</h3>
          <div class="hint">OpenCollar LP0 Replay tool helps replay, decrypt, and decode LoRaWAN uplinks captured as Semtech UDP JSONL logs.</div>
          <div class="hint">Use it to validate uplink pipelines, tune forwarders, and inspect payloads during field tests.</div>
        </div>
      </div>
    """
    return render_simple_page(
        title="About",
        subtitle="Product info and organization details.",
        body_html=body_html,
        active_page="about",
    )


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    user_id = get_user_id()
    allowed, retry_after = check_rate_limit("scan", user_id)
    if not allowed:
        return render_main_page(
            [f"Rate limit exceeded. Try again in {retry_after} seconds."],
            "error",
            stored_logs=list_stored_logs(),
        )
    logfile = request.files.get("logfile")
    stored_log_id = request.form.get("stored_log_id", "").strip()
    redirect_to = request.form.get("redirect_to", "").strip()
    stored_logs = list_stored_logs()
    selected_filename = ""
    selected_stored_id = stored_log_id

    stream = None
    if logfile and logfile.filename:
        size_hint = logfile.content_length
        ok, message = check_user_log_quota(user_id, new_bytes=size_hint)
        if not ok:
            return render_main_page(
                [message],
                "error",
                form_values=request.form,
                stored_logs=stored_logs,
                selected_stored_id=selected_stored_id,
            )
        entry = store_uploaded_log(logfile, user_id)
        audit_log(
            "log_uploaded",
            {"log_id": entry["id"], "filename": entry["filename"], "size": entry.get("size", 0)},
        )
        ok, message = enforce_user_log_quota_after_store(user_id, entry)
        if not ok:
            return render_main_page(
                [message],
                "error",
                form_values=request.form,
                stored_logs=stored_logs,
                selected_stored_id=selected_stored_id,
            )
        selected_filename = entry["filename"]
        selected_stored_id = entry["id"]
        stored_logs = list_stored_logs()
        if redirect_to == "files":
            return redirect(url_for("files_page"))
        stream = open(entry["path"], "rb")
    elif stored_log_id:
        entry = get_stored_log_entry(stored_log_id)
        if entry:
            selected_filename = entry["filename"]
            stream = open(entry["path"], "rb")

    if stream is None:
        if redirect_to == "files":
            return redirect(url_for("files_page"))
        return render_main_page(
            ["Please upload a logfile or select a stored logfile."],
            "error",
            form_values=request.form,
            stored_logs=stored_logs,
            selected_stored_id=selected_stored_id,
        )

    with stream:
        parsed, gateways, devaddrs, scan_errors = scan_logfile(stream)
    summary_lines = [
        "Logfile scan summary:",
        f"Uplinks (valid)={len(parsed)}",
        format_list("Gateway EUI", gateways),
        format_list("DevAddr (hex)", devaddrs),
    ]

    if scan_errors:
        error_lines = summary_lines + [
            f"Validation errors={len(scan_errors)}."
        ]
        preview = scan_errors[:10]
        error_lines.extend(preview)
        if len(scan_errors) > len(preview):
            error_lines.append(f"... (+{len(scan_errors) - len(preview)} more)")
        return render_main_page(
            error_lines,
            "error",
            form_values=request.form,
            selected_filename=selected_filename,
            stored_logs=stored_logs,
            selected_stored_id=selected_stored_id,
        )

    if not parsed:
        return render_main_page(
            summary_lines + ["No valid uplinks found."],
            "error",
            form_values=request.form,
            selected_filename=selected_filename,
            stored_logs=stored_logs,
            selected_stored_id=selected_stored_id,
        )

    scan_token = store_scan_result(parsed, gateways, devaddrs, selected_filename, selected_stored_id)
    audit_log(
        "log_scanned",
        {"scan_token": scan_token, "log_id": selected_stored_id, "filename": selected_filename},
    )
    return render_main_page(
        summary_lines + ["Scan complete. Ready to replay or decrypt."],
        "success",
        form_values=request.form,
        scan_token=scan_token,
        selected_filename=selected_filename,
        stored_logs=stored_logs,
        selected_stored_id=selected_stored_id,
    )


@app.route("/replay/status", methods=["GET"])
@login_required
def replay_status():
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify({"error": "missing_token"}), 400
    entry = get_replay_job(token)
    if not entry:
        return jsonify({"error": "not_found"}), 404
    since_raw = request.args.get("since", "0").strip()
    try:
        since = int(since_raw)
    except ValueError:
        since = 0
    with REPLAY_LOCK:
        lines = entry["log_lines"][since:]
        payload = {
            "status": entry["status"],
            "total": entry["total"],
            "sent": entry["sent"],
            "errors": entry["errors"],
            "host": entry["host"],
            "port": entry["port"],
            "delay_ms": entry["delay_ms"],
            "lines": lines,
            "count": len(entry["log_lines"]),
        }
    return jsonify(payload)


@app.route("/replay/stop", methods=["POST"])
@login_required
def replay_stop():
    token = request.form.get("replay_token", "").strip()
    scan_token = request.form.get("scan_token", "").strip()
    if token:
        entry = get_replay_job(token)
        if entry and entry.get("status") == "running":
            audit_log("replay_stopped", {"replay_token": token, "scan_token": scan_token})
            send_time_ms = int(time.time() * 1000)
            append_replay_log(
                token,
                {
                    "index": "",
                    "status": "Stopped",
                    "send_time_ms": send_time_ms,
                    "gateway": "",
                    "fcnt": "",
                    "freq": "",
                    "size": "",
                    "message": "Replay stopped by user.",
                    "css": "err",
                },
            )
            update_replay_job(token, status="stopped")
    return redirect(url_for("replay", scan_token=scan_token, replay_token=token))


@app.route("/replay/resume", methods=["POST"])
@login_required
def replay_resume():
    token = request.form.get("replay_token", "").strip()
    scan_token = request.form.get("scan_token", "").strip()
    entry = get_replay_job(token) if token else None
    if not entry or entry.get("status") != "stopped":
        return redirect(url_for("replay", scan_token=scan_token))
    cached = get_scan_result(scan_token)
    if not cached:
        return redirect(url_for("replay", scan_token=scan_token))

    parsed, _gateways, _devaddrs, _selected_filename, _stored_log_id = cached
    start_index = min(int(entry.get("current_index", 0)), len(parsed))
    host = entry.get("host", "127.0.0.1")
    port = int(entry.get("port", 1700))
    delay_ms = int(entry.get("delay_ms", 500))
    override_rxpk = bool(entry.get("override_rxpk", False))
    sent = int(entry.get("sent", 0))
    errors = int(entry.get("errors", 0))
    log_lines = list(entry.get("log_lines", []))

    job_token = store_replay_job(
        len(parsed),
        host,
        port,
        delay_ms,
        start_index=start_index,
        sent=sent,
        errors=errors,
        log_lines=log_lines,
        override_rxpk=override_rxpk,
    )
    thread = threading.Thread(
        target=run_replay_job,
        args=(job_token, parsed, host, port, delay_ms, start_index, sent, errors),
        daemon=True,
    )
    thread.start()
    audit_log("replay_resumed", {"replay_token": job_token, "scan_token": scan_token})
    return redirect(url_for("replay", scan_token=scan_token, replay_token=job_token))


@app.route("/replay", methods=["GET", "POST"])
@login_required
def replay():
    user_id = get_user_id()
    scan_token = (request.values.get("scan_token") or "").strip()
    back_url = resolve_back_url(url_for("index"))
    if not scan_token:
        return render_replay_page(
            summary_lines=["Scan a logfile first."],
            summary_class="error",
            back_url=back_url,
        )

    cached = get_scan_result(scan_token)
    if not cached:
        return render_replay_page(
            summary_lines=["Scan expired or not found. Please upload the logfile again."],
            summary_class="error",
            scan_token=scan_token,
            back_url=back_url,
        )

    parsed, gateways, devaddrs, selected_filename, _stored_log_id = cached
    summary_lines = [
        "Logfile scan summary:",
        f"Uplinks (valid)={len(parsed)}",
        format_list("Gateway EUI", gateways),
        format_list("DevAddr (hex)", devaddrs),
    ]

    replay_token = request.args.get("replay_token", "").strip()
    replay_job = get_replay_job(replay_token) if replay_token else None

    if request.method == "GET":
        form_values = None
        replay_total = 0
        replay_status = ""
        result_lines = None
        result_class = ""
        if replay_token and replay_job:
            form_values = {
                "host": replay_job.get("host", "127.0.0.1"),
                "port": str(replay_job.get("port", "1700")),
                "delay_ms": str(replay_job.get("delay_ms", "500")),
                "override_rxpk": replay_job.get("override_rxpk", False),
            }
            replay_total = replay_job.get("total", 0)
            replay_status = replay_job.get("status", "")
        elif replay_token and not replay_job:
            result_lines = ["Replay job not found or expired."]
            result_class = "error"
        return render_replay_page(
            form_values=form_values,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="success",
            result_lines=result_lines,
            result_class=result_class,
            replay_token=replay_token if replay_job else "",
            replay_total=replay_total,
            replay_status=replay_status,
            back_url=back_url,
        )

    allowed, retry_after = check_rate_limit("replay", user_id)
    if not allowed:
        return render_replay_page(
            form_values=request.form,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="success",
            result_lines=[f"Rate limit exceeded. Try again in {retry_after} seconds."],
            result_class="error",
            back_url=back_url,
        )

    host = request.form.get("host", "").strip() or "127.0.0.1"
    port_raw = request.form.get("port", "1700").strip()
    delay_raw = request.form.get("delay_ms", "500").strip()
    override_rxpk = request.form.get("override_rxpk", "").strip().lower() in ("1", "true", "yes", "on")

    try:
        port = int(port_raw)
    except ValueError:
        return render_replay_page(
            form_values=request.form,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="success",
            result_lines=[f"Invalid UDP port: {port_raw}"],
            result_class="error",
            back_url=back_url,
        )

    try:
        delay_ms = int(delay_raw)
        if delay_ms < 0:
            raise ValueError("delay must be non-negative")
    except ValueError:
        return render_replay_page(
            form_values=request.form,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="success",
            result_lines=[f"Invalid delay in milliseconds: {delay_raw}"],
            result_class="error",
            back_url=back_url,
        )

    if not parsed:
        return render_replay_page(
            form_values=request.form,
            scan_token=scan_token,
            selected_filename=selected_filename,
            summary_lines=summary_lines,
            summary_class="error",
            result_lines=["No valid uplinks found."],
            result_class="error",
            back_url=back_url,
        )

    job_token = store_replay_job(len(parsed), host, port, delay_ms, override_rxpk=override_rxpk)
    audit_log(
        "replay_started",
        {
            "replay_token": job_token,
            "scan_token": scan_token,
            "host": host,
            "port": port,
            "delay_ms": delay_ms,
            "override_rxpk": override_rxpk,
        },
    )
    thread = threading.Thread(
        target=run_replay_job,
        args=(job_token, parsed, host, port, delay_ms, 0, 0, 0),
        daemon=True,
    )
    thread.start()
    return redirect(url_for("replay", scan_token=scan_token, replay_token=job_token))


def get_missing_keys(devaddrs, credentials):
    missing = []
    for devaddr in devaddrs:
        entry = credentials.get(devaddr, {})
        nwk = entry.get("nwk_skey", "")
        app = entry.get("app_skey", "")
        if not nwk or not app or len(nwk) != 32 or len(app) != 32:
            missing.append(devaddr)
    return missing


@app.route("/decode", methods=["GET", "POST"])
@login_required
def decode():
    user_id = get_user_id()
    scan_token = request.form.get("scan_token") or request.args.get("scan_token", "")
    scan_token = scan_token.strip()
    back_url = resolve_back_url(url_for("index"))
    if not scan_token:
        return render_main_page(["Scan a logfile first."], "error", stored_logs=list_stored_logs())

    cached = get_scan_result(scan_token)
    if not cached:
        return render_main_page(
            ["Scan expired or not found. Please upload the logfile again."],
            "error",
            stored_logs=list_stored_logs(),
        )

    parsed, gateways, devaddrs, selected_filename, stored_log_id = cached
    credentials = load_credentials()
    missing_keys = get_missing_keys(devaddrs, credentials)
    summary_lines = [
        "Logfile scan summary:",
        f"Uplinks (valid)={len(parsed)}",
        format_list("Gateway EUI", gateways),
        format_list("DevAddr (hex)", devaddrs),
    ]
    decoders = list_decoders()
    selected_decoder = request.form.get("decoder_id", "raw")
    decode_results = None
    decode_columns = []
    export_token = request.form.get("export_token", "").strip()
    result_class = "success"

    action = request.form.get("action", "").strip()
    if action == "add_device":
        devaddr_raw = request.form.get("new_devaddr", "").strip()
        name_val = request.form.get("new_name", "").strip()
        nwk_val = request.form.get("new_nwk", "").strip()
        app_val = request.form.get("new_app", "").strip()
        if not devaddr_raw:
            summary_lines = ["DevAddr is required to add a device."]
            result_class = "error"
        else:
            try:
                devaddr = normalize_devaddr(devaddr_raw)
            except ValueError as exc:
                summary_lines = [str(exc)]
                result_class = "error"
            else:
                if (nwk_val or app_val) and not (nwk_val and app_val):
                    summary_lines = ["Provide both NwkSKey and AppSKey, or leave both empty."]
                    result_class = "error"
                else:
                    entry = credentials.get(devaddr, {})
                    if name_val:
                        entry["name"] = name_val
                    if nwk_val and app_val:
                        try:
                            entry["nwk_skey"] = normalize_skey(nwk_val, f"NwkSKey for {devaddr}")
                            entry["app_skey"] = normalize_skey(app_val, f"AppSKey for {devaddr}")
                        except ValueError as exc:
                            summary_lines = [str(exc)]
                            result_class = "error"
                            return render_decode_page(
                                scan_token=scan_token,
                                devaddrs=devaddrs,
                                credentials=credentials,
                                summary_lines=summary_lines,
                                result_class=result_class,
                                missing_keys=missing_keys,
                                decoders=decoders,
                                selected_decoder=selected_decoder,
                                decode_results=decode_results,
                                decode_columns=decode_columns,
                                selected_filename=selected_filename,
                                export_token=export_token,
                                back_url=back_url,
                            )
                    entry["updated_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                    credentials[devaddr] = entry
                    save_credentials(credentials)
                    summary_lines = [f"Device {devaddr} saved."]
                    result_class = "success"

        missing_keys = get_missing_keys(devaddrs, credentials)
        return render_decode_page(
            scan_token=scan_token,
            devaddrs=devaddrs,
            credentials=credentials,
            summary_lines=summary_lines,
            result_class=result_class,
            missing_keys=missing_keys,
            decoders=decoders,
            selected_decoder=selected_decoder,
            decode_results=decode_results,
            decode_columns=decode_columns,
            selected_filename=selected_filename,
            export_token=export_token,
            back_url=back_url,
        )

    if action == "save_results":
        cached_rows = get_decode_result(export_token) if export_token else None
        if not cached_rows:
            summary_lines = ["Decoded results not found. Please decode again."]
            result_class = "error"
        else:
            columns = []
            seen = set()
            for row in cached_rows:
                flat = row.get("decoded_flat") or {}
                for key in flat.keys():
                    if key not in seen:
                        seen.add(key)
                        columns.append(key)
            decode_results = cached_rows
            decode_columns = build_decode_columns_meta(columns, FIELD_META)
            entry = store_saved_decode_result(
                cached_rows,
                stored_log_id,
                selected_filename,
                selected_decoder,
                user_id,
            )
            summary_lines = [f"Results saved for {entry['filename']}."]
            result_class = "success"
            audit_log(
                "decode_saved",
                {
                    "saved_id": entry["id"],
                    "log_id": stored_log_id,
                    "filename": entry["filename"],
                    "decoder_id": selected_decoder,
                },
            )

    if action == "upload_decoder":
        if not DECODER_UPLOADS_ENABLED:
            summary_lines = ["Decoder uploads are disabled."]
            result_class = "error"
        else:
            allowed, retry_after = check_rate_limit("decoder_upload", user_id)
            if not allowed:
                summary_lines = [f"Rate limit exceeded. Try again in {retry_after} seconds."]
                result_class = "error"
            else:
                decoder_file = request.files.get("decoder_file")
                if not decoder_file or not decoder_file.filename:
                    summary_lines = ["Please choose a decoder file to upload."]
                    result_class = "error"
                else:
                    filename = secure_filename(decoder_file.filename)
                    if not filename.lower().endswith(".js"):
                        summary_lines = ["Decoder file must be a .js file."]
                        result_class = "error"
                    else:
                        ensure_data_dirs()
                        path = os.path.join(DECODER_DIR, filename)
                        decoder_file.save(path)
                        summary_lines = [f"Decoder uploaded: {filename}"]
                        result_class = "success"
                        decoders = list_decoders()
                        audit_log("decoder_uploaded", {"filename": filename})

    if action == "decode":
        allowed, retry_after = check_rate_limit("decode", user_id)
        progress_id = request.form.get("progress_id", "").strip()
        if not allowed:
            summary_lines = [f"Rate limit exceeded. Try again in {retry_after} seconds."]
            result_class = "error"
            set_decode_progress(progress_id, user_id, 0, 0, done=True)
        elif missing_keys:
            summary_lines = ["Missing keys. Save keys before decoding."]
            result_class = "error"
            set_decode_progress(progress_id, user_id, 0, 0, done=True)
        else:
            try:
                decoder_func = load_decoder(selected_decoder)
            except Exception as exc:
                summary_lines = [f"Decoder error: {exc}"]
                result_class = "error"
                set_decode_progress(progress_id, user_id, 0, 0, done=True)
            else:
                rows = []
                decoded_columns = []
                seen_columns = set()
                row_index = 0
                ok = 0
                errors = 0
                total_items = len(parsed)
                set_decode_progress(progress_id, user_id, 0, total_items, done=False)
                for idx, rec in enumerate(parsed, start=1):
                    rxpk = rec["rxpk"]
                    gateway_eui = rec["gateway_eui"]
                    time_str = rxpk.get("time", "")
                    freq = rxpk.get("freq", "")
                    devaddr = ""
                    fcnt = ""
                    fport = ""

                    try:
                        uplink = parse_uplink(rxpk)
                        devaddr = uplink["devaddr"]
                        fcnt = uplink["fcnt"]
                        fport = uplink["fport"] if uplink["fport"] is not None else ""
                        keys = credentials.get(devaddr, {})
                        nwk_skey = hex_to_bytes(keys["nwk_skey"], "NwkSKey")
                        app_skey = hex_to_bytes(keys["app_skey"], "AppSKey")
                        key = app_skey if uplink["fport"] not in (0, None) else nwk_skey
                        decrypted = lorawan_decrypt_payload(
                            key, uplink["devaddr_le"], uplink["fcnt"], uplink["frm_payload"], direction=0
                        )
                        payload_hex = decrypted.hex().upper()
                        if uplink["fport"] == 29:
                            messages = unpack_port29_messages(decrypted)
                            if not messages:
                                raise ValueError("Port 29 payload contained no messages.")
                            for message in messages:
                                row_index += 1
                                status = "Decoded"
                                css = "ok"
                                decoded_data = None
                                decoded_raw = None
                                decoded_preview = ""
                                error_msg = ""
                                time_unix = message.get("timestamp")
                                time_utc = format_unix_utc(time_unix)
                                message_payload = message.get("payload", b"")
                                message_port = message.get("port")
                                message_payload_hex = message_payload.hex().upper()
                                try:
                                    if message_port == 29:
                                        decoded_raw = None
                                        decoded_data = {}
                                    else:
                                        decoded_raw = decoder_func(message_payload, message_port, devaddr, rxpk)
                                        if isinstance(decoded_raw, dict) and "data" in decoded_raw and len(decoded_raw) <= 3:
                                            decoded_data = decoded_raw.get("data")
                                        else:
                                            decoded_data = decoded_raw
                                    decoded_preview = json.dumps(decoded_data, ensure_ascii=True)
                                    ok += 1
                                except Exception as exc:
                                    status = "Error"
                                    css = "err"
                                    error_msg = str(exc)
                                    decoded_preview = error_msg
                                    errors += 1

                                decoded_flat = flatten_decoded(decoded_data)
                                for key in decoded_flat.keys():
                                    if key not in seen_columns:
                                        seen_columns.add(key)
                                        decoded_columns.append(key)

                                rows.append(
                                    {
                                        "index": row_index,
                                        "status": status,
                                        "devaddr": devaddr,
                                        "fcnt": fcnt,
                                        "fport": message_port if message_port is not None else "",
                                        "time": time_str,
                                        "time_unix": time_unix if time_unix is not None else "",
                                        "time_utc": time_utc,
                                        "gateway_eui": gateway_eui,
                                        "freq": freq,
                                        "payload_hex": message_payload_hex,
                                        "decoded": decoded_data,
                                        "decoded_raw": decoded_raw,
                                        "decoded_flat": decoded_flat,
                                        "error": error_msg,
                                        "decoded_preview": decoded_preview,
                                        "css": css,
                                    }
                                )
                        else:
                            row_index += 1
                            status = "Decoded"
                            css = "ok"
                            decoded_data = None
                            decoded_raw = None
                            decoded_preview = ""
                            error_msg = ""
                            decoded_raw = decoder_func(decrypted, uplink["fport"], devaddr, rxpk)
                            if isinstance(decoded_raw, dict) and "data" in decoded_raw and len(decoded_raw) <= 3:
                                decoded_data = decoded_raw.get("data")
                            else:
                                decoded_data = decoded_raw
                            decoded_preview = json.dumps(decoded_data, ensure_ascii=True)
                            decoded_flat = flatten_decoded(decoded_data)
                            for key in decoded_flat.keys():
                                if key not in seen_columns:
                                    seen_columns.add(key)
                                    decoded_columns.append(key)
                            ok += 1

                            rows.append(
                                {
                                    "index": row_index,
                                    "status": status,
                                    "devaddr": devaddr,
                                    "fcnt": fcnt,
                                    "fport": fport,
                                    "time": time_str,
                                    "time_unix": "",
                                    "time_utc": "",
                                    "gateway_eui": gateway_eui,
                                    "freq": freq,
                                    "payload_hex": payload_hex,
                                    "decoded": decoded_data,
                                    "decoded_raw": decoded_raw,
                                    "decoded_flat": decoded_flat,
                                    "error": error_msg,
                                    "decoded_preview": decoded_preview,
                                    "css": css,
                                }
                            )
                    except Exception as exc:
                        row_index += 1
                        status = "Error"
                        css = "err"
                        error_msg = str(exc)
                        decoded_preview = error_msg
                        errors += 1
                        rows.append(
                            {
                                "index": row_index,
                                "status": status,
                                "devaddr": devaddr,
                                "fcnt": fcnt,
                                "fport": fport,
                                "time": time_str,
                                "time_unix": "",
                                "time_utc": "",
                                "gateway_eui": gateway_eui,
                                "freq": freq,
                                "payload_hex": "",
                                "decoded": None,
                                "decoded_raw": None,
                                "decoded_flat": {},
                                "error": error_msg,
                                "decoded_preview": decoded_preview,
                                "css": css,
                            }
                        )
                    finally:
                        set_decode_progress(progress_id, user_id, idx, total_items, done=False)

                decode_results = rows
                decode_columns = build_decode_columns_meta(decoded_columns, FIELD_META)
                export_token = store_decode_result(rows)
                set_decode_progress(progress_id, user_id, total_items, total_items, done=True)
                summary_lines = [
                    "Decode complete.",
                    f"Decoded={ok}, errors={errors}",
                ]
                result_class = "success" if errors == 0 else "error"
                audit_log(
                    "decode_completed",
                    {
                        "scan_token": scan_token,
                        "decoder_id": selected_decoder,
                        "decoded": ok,
                        "errors": errors,
                    },
                )

    return render_decode_page(
        scan_token=scan_token,
        devaddrs=devaddrs,
        credentials=credentials,
        summary_lines=summary_lines,
        result_class=result_class,
        missing_keys=missing_keys,
        decoders=decoders,
        selected_decoder=selected_decoder,
        decode_results=decode_results,
        decode_columns=decode_columns,
        selected_filename=selected_filename,
        export_token=export_token,
        back_url=back_url,
    )


@app.route("/decode-progress", methods=["GET"])
@login_required
def decode_progress():
    user_id = get_user_id()
    progress_id = request.args.get("progress_id", "").strip()
    if not progress_id:
        return jsonify({"error": "missing_progress_id"}), 400
    entry = get_decode_progress(progress_id, user_id)
    if not entry:
        return jsonify({"error": "not_found"}), 404
    return jsonify(
        {
            "completed": entry.get("completed", 0),
            "total": entry.get("total", 0),
            "done": entry.get("done", False),
        }
    )


@app.route("/devices", methods=["GET", "POST"])
@login_required
def device_keys():
    scan_token = request.form.get("scan_token") or request.args.get("scan_token", "")
    scan_token = scan_token.strip()
    back_url = resolve_back_url(url_for("index"))
    credentials = load_credentials()
    summary_lines = []
    result_class = "success"
    scan_summary_lines = []
    scan_filename = ""

    if request.args.get("show_scan") and scan_token:
        cached = get_scan_result(scan_token)
        if cached:
            parsed, gateways, devaddrs, scan_filename, _stored_log_id = cached
            scan_summary_lines = [
                "Logfile scan summary:",
                f"Uplinks (valid)={len(parsed)}",
                format_list("Gateway EUI", gateways),
                format_list("DevAddr (hex)", devaddrs),
            ]

    action = request.form.get("action", "").strip()
    if action == "delete_device":
        devaddr = request.form.get("delete_devaddr", "").strip()
        if not devaddr:
            summary_lines = ["Select a device to remove."]
            result_class = "error"
        elif devaddr not in credentials:
            summary_lines = [f"Device {devaddr} not found."]
            result_class = "error"
        else:
            credentials.pop(devaddr, None)
            save_credentials(credentials)
            summary_lines = [f"Device {devaddr} removed."]
            result_class = "success"
            audit_log("device_removed", {"devaddr": devaddr})
        return render_device_keys_page(
            credentials,
            summary_lines=summary_lines,
            result_class=result_class,
            scan_token=scan_token,
            scan_summary_lines=scan_summary_lines,
            scan_filename=scan_filename,
            back_url=back_url,
        )

    if action == "save_keys":
        updated = 0
        errors = []
        for devaddr in list(credentials.keys()):
            name_val = request.form.get(f"name_{devaddr}", "").strip()
            nwk_val = request.form.get(f"nwk_{devaddr}", "").strip()
            app_val = request.form.get(f"app_{devaddr}", "").strip()
            entry = credentials.get(devaddr, {})
            if name_val:
                entry["name"] = name_val
            if nwk_val or app_val:
                if not nwk_val or not app_val:
                    errors.append(f"Both keys required for {devaddr}.")
                else:
                    try:
                        entry["nwk_skey"] = normalize_skey(nwk_val, f"NwkSKey for {devaddr}")
                        entry["app_skey"] = normalize_skey(app_val, f"AppSKey for {devaddr}")
                    except ValueError as exc:
                        errors.append(str(exc))
            entry["updated_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            credentials[devaddr] = entry
            updated += 1
        if errors:
            summary_lines = ["Key update errors:"] + errors
            result_class = "error"
        else:
            summary_lines = [f"Updated {updated} device(s)."]
            audit_log("device_keys_updated", {"updated": updated})
        save_credentials(credentials)

    if action == "add_device":
        devaddr_raw = request.form.get("new_devaddr", "").strip()
        name_val = request.form.get("new_name", "").strip()
        nwk_val = request.form.get("new_nwk", "").strip()
        app_val = request.form.get("new_app", "").strip()
        if not devaddr_raw:
            summary_lines = ["DevAddr is required to add a device."]
            result_class = "error"
        else:
            try:
                devaddr = normalize_devaddr(devaddr_raw)
            except ValueError as exc:
                summary_lines = [str(exc)]
                result_class = "error"
            else:
                if (nwk_val or app_val) and not (nwk_val and app_val):
                    summary_lines = ["Provide both NwkSKey and AppSKey, or leave both empty."]
                    result_class = "error"
                else:
                    entry = credentials.get(devaddr, {})
                    if name_val:
                        entry["name"] = name_val
                    if nwk_val and app_val:
                        try:
                            entry["nwk_skey"] = normalize_skey(nwk_val, f"NwkSKey for {devaddr}")
                            entry["app_skey"] = normalize_skey(app_val, f"AppSKey for {devaddr}")
                        except ValueError as exc:
                            summary_lines = [str(exc)]
                            result_class = "error"
                            return render_device_keys_page(
                                credentials,
                                summary_lines=summary_lines,
                                result_class=result_class,
                                scan_token=scan_token,
                                back_url=back_url,
                            )
                    entry["updated_at"] = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                    credentials[devaddr] = entry
                    save_credentials(credentials)
                    summary_lines = [f"Device {devaddr} saved."]
                    result_class = "success"
                    audit_log("device_added", {"devaddr": devaddr})

    return render_device_keys_page(
        credentials,
        summary_lines=summary_lines,
        result_class=result_class,
        scan_token=scan_token,
        scan_summary_lines=scan_summary_lines,
        scan_filename=scan_filename,
        back_url=back_url,
    )


def build_export_rows(rows):
    decoded_columns = []
    seen_columns = set()
    for row in rows:
        flat = row.get("decoded_flat") or {}
        for key in flat.keys():
            if key not in seen_columns:
                seen_columns.add(key)
                decoded_columns.append(key)
    columns_meta = build_decode_columns_meta(decoded_columns, FIELD_META)
    ordered_columns = [entry["key"] for entry in columns_meta]

    def normalize_flat_value(value):
        if value is None:
            return ""
        if isinstance(value, (str, int, float, bool)):
            return value
        return json.dumps(value, ensure_ascii=True)

    export_rows = []
    for row in rows:
        export_row = {
            "index": row.get("index"),
            "status": row.get("status"),
            "devaddr": row.get("devaddr"),
            "fcnt": row.get("fcnt"),
            "fport": row.get("fport"),
            "time": row.get("time"),
            "time_unix": row.get("time_unix"),
            "time_utc": row.get("time_utc"),
            "gateway_eui": row.get("gateway_eui"),
            "freq": row.get("freq"),
            "payload_hex": row.get("payload_hex"),
            "decoded": json.dumps(row.get("decoded"), ensure_ascii=True) if row.get("decoded") is not None else "",
            "decoded_raw": json.dumps(row.get("decoded_raw"), ensure_ascii=True) if row.get("decoded_raw") is not None else "",
            "error": row.get("error"),
        }
        flat = row.get("decoded_flat") or {}
        for key in ordered_columns:
            export_row[key] = normalize_flat_value(flat.get(key))
        export_rows.append(export_row)
    return export_rows


@app.route("/export/<fmt>", methods=["GET"])
@login_required
def export_results(fmt):
    token = request.args.get("token", "").strip()
    rows = get_decode_result(token)
    if not rows:
        return "No export data available.", 404

    export_rows = build_export_rows(rows)
    if not export_rows:
        return "No export data available.", 404

    if fmt == "json":
        buffer = io.BytesIO(json.dumps(export_rows, indent=2).encode("utf-8"))
        buffer.seek(0)
        return send_file(buffer, mimetype="application/json", as_attachment=True, download_name="decoded_payloads.json")

    if fmt == "csv":
        buffer = io.StringIO()
        fieldnames = list(export_rows[0].keys())
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(export_rows)
        csv_bytes = io.BytesIO(buffer.getvalue().encode("utf-8"))
        csv_bytes.seek(0)
        return send_file(csv_bytes, mimetype="text/csv", as_attachment=True, download_name="decoded_payloads.csv")

    return "Unsupported export format.", 400


@app.route("/results/export/<fmt>", methods=["GET"])
@login_required
def export_saved_results(fmt):
    saved_id = request.args.get("saved_id", "").strip()
    entry, rows = load_saved_decode_rows(saved_id)
    if not entry or rows is None:
        return "Saved results not found.", 404

    export_rows = build_export_rows(rows)
    if not export_rows:
        return "No export data available.", 404

    base_name = secure_filename(entry.get("filename") or "decoded_payloads") or "decoded_payloads"
    if fmt == "json":
        buffer = io.BytesIO(json.dumps(export_rows, indent=2).encode("utf-8"))
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"decoded_{base_name}.json",
        )

    if fmt == "csv":
        buffer = io.StringIO()
        fieldnames = list(export_rows[0].keys())
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(export_rows)
        csv_bytes = io.BytesIO(buffer.getvalue().encode("utf-8"))
        csv_bytes.seek(0)
        return send_file(
            csv_bytes,
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"decoded_{base_name}.csv",
        )

    return "Unsupported export format.", 400


@app.route("/analyze", methods=["GET"])
@login_required
def analyze_results():
    token = request.args.get("token", "").strip()
    saved_id = request.args.get("saved_id", "").strip()
    scan_token = request.args.get("scan_token", "").strip()
    rows = None
    source_filename = ""

    if saved_id:
        entry, rows = load_saved_decode_rows(saved_id)
        if not entry or rows is None:
            return render_simple_page(
                title="Analyze",
                subtitle="Explore decoded payloads.",
                body_html="<div class=\"result error\">Saved results not found.</div>",
                active_page="files",
                page_title="Analyze results",
            )
        source_filename = entry.get("filename") or "Saved results"
    elif token:
        rows = get_decode_result(token)
        if not rows:
            return render_simple_page(
                title="Analyze",
                subtitle="Explore decoded payloads.",
                body_html="<div class=\"result error\">Decoded results not found.</div>",
                active_page="decoders",
                page_title="Analyze results",
            )
        if scan_token:
            cached = get_scan_result(scan_token)
            if cached:
                _parsed, _gateways, _devaddrs, scan_filename, _stored_log_id = cached
                source_filename = scan_filename
    else:
        return render_simple_page(
            title="Analyze",
            subtitle="Explore decoded payloads.",
            body_html="<div class=\"result error\">No decoded results selected.</div>",
            active_page="files",
            page_title="Analyze results",
        )

    if not source_filename:
        source_filename = "Decoded results"

    analyze_payload = json.dumps(rows or [], ensure_ascii=True).replace("</", "<\\/")
    field_meta_payload = json.dumps(FIELD_META or {}, ensure_ascii=True).replace("</", "<\\/")
    body_html = f"""
      <style>
        .card .subtitle {{ margin-bottom: 1rem; }}
      </style>
      <div class="result error" id="analysis_error" style="display:none;"></div>
      <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3"></script>
      <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.0.1/dist/chartjs-plugin-zoom.min.js"></script>
      <script type="application/json" id="analysis_payload">{analyze_payload}</script>
      <script type="application/json" id="analysis_field_meta">{field_meta_payload}</script>
      <details class="chart-card" open>
        <summary>Decoded message summary</summary>
        <div class="analytics-hint" id="message_summary_hint"></div>
        <div class="analysis-table-wrapper" style="margin-top:0.6rem;">
          <table class="analysis-table">
            <thead><tr><th>Port</th><th>Message type</th><th>Messages</th></tr></thead>
            <tbody id="message_summary_body"></tbody>
          </table>
        </div>
      </details>

      <details class="chart-card" open>
        <summary>Simple analytics (tables, charts & statistics)</summary>
        <div class="analytics-controls">
          <div class="control-row">
            <label for="field_select">Field (X)</label>
            <select id="field_select"></select>
          </div>
          <div class="control-row">
            <label for="field_select_2">Second field (line - optional)</label>
            <select id="field_select_2">
              <option value="">-</option>
            </select>
          </div>
          <div class="control-row">
            <label for="field_select_y">Field (Y, scatter - optional)</label>
            <select id="field_select_y">
              <option value="">-</option>
            </select>
          </div>
          <div class="control-row">
            <label for="bucket_select">Time bucket</label>
            <select id="bucket_select">
              <option value="none" selected>None</option>
              <option value="minute">Minute</option>
              <option value="hour">Hour</option>
              <option value="day">Day</option>
            </select>
          </div>
          <div class="control-row">
            <label for="agg_select">Aggregation</label>
            <select id="agg_select">
              <option value="mean" selected>Average</option>
              <option value="min">Min</option>
              <option value="max">Max</option>
              <option value="sum">Sum</option>
              <option value="count">Count</option>
              <option value="median">Median</option>
              <option value="stdev">Std.dev.</option>
            </select>
          </div>
          <div class="control-row">
            <label for="chart_type">Chart type</label>
            <select id="chart_type">
              <option value="line" selected>Line (time series)</option>
              <option value="bar">Bar</option>
              <option value="scatter">Scatter (X vs Y)</option>
              <option value="hist">Histogram</option>
            </select>
          </div>
          <div class="control-row">
            <label for="port_filter">Filter: Port</label>
            <input id="port_filter" type="text" placeholder="e.g. 15">
          </div>
          <div class="control-row">
            <label for="start_time">From</label>
            <input id="start_time" type="datetime-local">
          </div>
          <div class="control-row">
            <label for="end_time">To</label>
            <input id="end_time" type="datetime-local">
          </div>
          <div class="control-row">
            <label>Outlier filter (X)</label>
            <div class="analytics-inline">
              <span class="analytics-hint">min</span>
              <input id="min_x" type="number" step="any" placeholder="auto">
              <span class="analytics-hint">max</span>
              <input id="max_x" type="number" step="any" placeholder="auto">
            </div>
            <div class="analytics-hint" id="x_range_hint"></div>
          </div>
          <div class="control-row" id="outlier_y_wrap" style="display:none;">
            <label>Outlier filter (Y)</label>
            <div class="analytics-inline">
              <span class="analytics-hint">min</span>
              <input id="min_y" type="number" step="any" placeholder="auto">
              <span class="analytics-hint">max</span>
              <input id="max_y" type="number" step="any" placeholder="auto">
            </div>
            <div class="analytics-hint" id="y_range_hint"></div>
          </div>
          <div class="control-row full-row">
            <label class="analytics-hint">&nbsp;</label>
            <button type="button" class="secondary-button" id="generate_chart"><span class="material-icons" aria-hidden="true">insights</span>Generate</button>
          </div>
        </div>

        <div class="section-divider"></div>
        <details class="stats-card" id="stats_panel" open style="display:none;">
          <summary id="stats_summary">Statistics</summary>
          <div id="stats_box"></div>
        </details>
        <div class="chart-wrapper" id="chart_panel" style="display:none;">
          <div class="chart-button-row">
            <button type="button" class="chart-toggle-button" id="chart_expand" title="Expand chart" aria-label="Expand chart">
              <span class="material-icons" aria-hidden="true">open_in_full</span>
            </button>
            <button type="button" class="chart-toggle-button chart-zoom-reset" id="chart_reset_zoom" title="Reset zoom" aria-label="Reset zoom">
              <span class="material-icons" aria-hidden="true">restart_alt</span>
            </button>
            <button type="button" class="chart-toggle-button chart-toggle-line" id="chart_toggle_line" title="Toggle line" aria-label="Toggle line">
              <span class="material-icons" aria-hidden="true">show_chart</span>
            </button>
            <button type="button" class="chart-toggle-button chart-toggle-points" id="chart_toggle_points" title="Toggle points" aria-label="Toggle points">
              <span class="material-icons" aria-hidden="true">scatter_plot</span>
            </button>
          </div>
          <canvas class="chart-canvas" id="chart_canvas" height="340"></canvas>
        </div>
        <div class="analysis-table-wrapper" id="analysis_table_panel" style="margin-top: 0.8rem; display:none;">
          <table class="analysis-table">
            <thead><tr id="analysis_table_head"></tr></thead>
            <tbody id="analysis_table_body"></tbody>
          </table>
        </div>
      </details>

      <div class="section-divider"></div>

      <details class="chart-card" open>
        <summary>Map</summary>
        <div class="map-controls">
          <div class="control-row">
            <label for="map_port_filter">Filter: Port (Map)</label>
            <select id="map_port_filter">
              <option value="">All ports</option>
            </select>
          </div>
          <div class="control-row">
            <label for="map_start_time">From (Map)</label>
            <input id="map_start_time" type="datetime-local">
          </div>
          <div class="control-row">
            <label for="map_end_time">To (Map)</label>
            <input id="map_end_time" type="datetime-local">
          </div>
          <div class="control-row">
            <label>Coordinate filter</label>
            <label class="analytics-hint"><input type="checkbox" id="ignore_zero_coords" checked> Ignore lat=0 or lon=0</label>
          </div>
          <div class="control-row full-row">
            <label class="analytics-hint">&nbsp;</label>
            <button type="button" class="secondary-button" id="generate_map"><span class="material-icons" aria-hidden="true">map</span>Generate Map</button>
          </div>
        </div>
        <div class="analytics-hint" id="map_message"></div>
        <div class="map-panel" id="map_panel" style="display:none;"></div>
        <div id="map_stats" style="margin-top:0.75rem;"></div>
        <div class="analysis-table-wrapper" style="margin-top: 0.8rem;">
          <table class="analysis-table">
            <thead><tr id="map_table_head"></tr></thead>
            <tbody id="map_table_body"></tbody>
          </table>
        </div>
      </details>

      <script>
        (() => {{
          try {{
            const payloadEl = document.getElementById("analysis_payload");
            const metaEl = document.getElementById("analysis_field_meta");
            const rows = payloadEl ? JSON.parse(payloadEl.textContent || "[]") : [];
            const fieldMeta = metaEl ? JSON.parse(metaEl.textContent || "{{}}") : {{}};
            const parseNumber = (value) => {{
              if (value === null || value === undefined || value === "") return null;
              if (typeof value === "number" && Number.isFinite(value)) return value;
              if (typeof value === "string") {{
                const parsed = Number(value);
                return Number.isFinite(parsed) ? parsed : null;
              }}
              return null;
            }};

          const parseTimestamp = (row) => {{
            const unix = parseNumber(row.time_unix);
            if (unix !== null) return unix * 1000;
            const raw = row.time_utc || "";
            if (!raw) return null;
            const parsed = Date.parse(raw.replace(" UTC", "Z"));
            return Number.isFinite(parsed) ? parsed : null;
          }};

          const normalizeField = (field) => {{
            return field ? field.replace(/^data\\./, "") : field;
          }};

          const getFieldMeta = (field) => {{
            if (!field) return null;
            return fieldMeta[field] || fieldMeta[normalizeField(field)] || null;
          }};

          const getFieldLabel = (field) => {{
            const meta = getFieldMeta(field);
            if (meta && meta.label) return meta.label;
            return normalizeField(field) || "";
          }};

          const getUnitLabel = (field) => {{
            const meta = getFieldMeta(field);
            if (meta && meta.unit) {{
              return meta.unit.symbol || meta.unit.label || "";
            }}
            return "";
          }};

          const getPrecision = (field) => {{
            const meta = getFieldMeta(field);
            if (!meta) return null;
            if (meta.isInteger) return 0;
            if (meta.precision !== undefined && meta.precision !== null) return meta.precision;
            return null;
          }};

          const trimZeros = (text) => {{
            if (text.includes(".")) {{
              return text.replace(/\\.0+$/, "").replace(/(\\.\\d*?)0+$/, "$1").replace(/\\.$/, "");
            }}
            return text;
          }};

          const formatNumber = (value, precision = null) => {{
            if (value === null || value === undefined || Number.isNaN(value)) return "";
            const num = Number(value);
            if (!Number.isFinite(num)) return "";
            if (precision !== null) {{
              const fixed = num.toFixed(precision);
              return precision > 0 ? trimZeros(fixed) : fixed;
            }}
            const text = String(num);
            if (/[eE]/.test(text)) return trimZeros(num.toFixed(6));
            return text;
          }};

          const formatValue = (field, value) => {{
            if (value === null || value === undefined || value === "") return "";
            if (typeof value === "number" || typeof value === "string") {{
              const precision = getPrecision(field);
              return formatNumber(value, precision);
            }}
            if (typeof value === "boolean") return value ? "1" : "0";
            return String(value);
          }};

          const formatFieldLabel = (field) => {{
            if (!field) return "";
            const base = getFieldLabel(field);
            const unit = getUnitLabel(field);
            return unit ? `${{base}} (${{unit}})` : base;
          }};

          const records = rows.map((row) => ({{
            status: row.status || "",
            devaddr: row.devaddr || "",
            fport: row.fport,
            timestamp: parseTimestamp(row),
            flat: row.decoded_flat || {{}},
            payload_hex: row.payload_hex || ""
          }}));

          const PORT_TO_TYPE = {{
            1: "lr_gps",
            2: "ublox_gps",
            3: "settings",
            4: "status",
            5: "lr_sat_data",
            6: "wifi_scan_aggregated",
            7: "ble_scan_aggregated",
            8: "rf_scan",
            9: "ublox_sat_data",
            10: "wifi_scan",
            11: "ble_scan",
            12: "fence",
            13: "ublox_short_message",
            14: "flash_status",
            15: "ble_cmdq",
            16: "ublox_resend_location",
            17: "rf_open_sky_detection",
            18: "timestamp",
            19: "external_switch_detection",
            20: "external_switch_detection_status",
            27: "memfault",
            28: "lr_messaging",
            29: "flash_log",
            30: "values",
            31: "messages",
            32: "commands"
          }};

          const guessMessageType = (flat) => {{
            const keys = flat ? Object.keys(flat).map((key) => normalizeField(key)) : [];
            const has = (...arr) => arr.some((key) => keys.includes(key));
            if (has("latitude", "longitude", "cog", "sog", "pDOP", "SIV", "fixType")) return "gnss_like";
            if (has("bat", "temp", "uptime", "locked", "reset", "acc_x", "acc_y", "acc_z")) return "status_like";
            if (has("wifi_scan_json")) return "wifi_scan";
            if (has("bt_scan_json")) return "ble_scan";
            if (has("rf_scan", "rf_scan_json")) return "rf_scan";
            if (has("opensky_json")) return "rf_open_sky_detection";
            if (has("fence", "fence_json")) return "fence";
            if (has("memfault_msg_hex")) return "memfault";
            return "unknown";
          }};

          const resolveMessageType = (port, sampleFlat) => {{
            if (PORT_TO_TYPE[port]) return PORT_TO_TYPE[port];
            return guessMessageType(sampleFlat);
          }};

          const renderMessageSummary = () => {{
            const counts = new Map();
            const samples = new Map();
            records.forEach((record) => {{
              const port = record.fport !== undefined && record.fport !== null ? record.fport : "(unknown)";
              counts.set(port, (counts.get(port) || 0) + 1);
              if (!samples.has(port)) samples.set(port, record.flat || {{}});
            }});
            const rowsSummary = Array.from(counts.entries())
              .sort((a, b) => b[1] - a[1])
              .map(([port, count]) => {{
                const portNumber = Number(port);
                const type = Number.isFinite(portNumber)
                  ? resolveMessageType(portNumber, samples.get(port))
                  : "unknown";
                return {{ port, type, count }};
              }});
            const body = document.getElementById("message_summary_body");
            if (body) {{
              body.innerHTML = rowsSummary.map((row) =>
                `<tr><td>${{row.port}}</td><td>${{row.type}}</td><td>${{row.count}}</td></tr>`
              ).join("");
            }}
            const hint = document.getElementById("message_summary_hint");
            if (hint) {{
              hint.textContent = rowsSummary.length
                ? `Total messages: ${{records.length}} • Unique ports: ${{rowsSummary.length}}`
                : "No decoded messages available.";
            }}
          }};

          const numericFields = (() => {{
            const found = new Set();
            records.forEach((record) => {{
              Object.entries(record.flat).forEach(([key, value]) => {{
                if (parseNumber(value) !== null) found.add(key);
              }});
            }});
            return Array.from(found).sort();
          }})();

          const pickBestLat = () => {{
            const preferred = ["data.latitude", "latitude", "lat", "gps_lat"];
            for (const field of preferred) {{
              if (numericFields.includes(field)) return field;
            }}
            return numericFields.find((field) => /lat/i.test(field)) || "";
          }};

          const pickBestLon = () => {{
            const preferred = ["data.longitude", "longitude", "lon", "lng", "gps_lon"];
            for (const field of preferred) {{
              if (numericFields.includes(field)) return field;
            }}
            return numericFields.find((field) => /(lon|lng)/i.test(field)) || "";
          }};

          const selectField = (id, includeEmpty) => {{
            const select = document.getElementById(id);
            if (!select) return;
            const empty = includeEmpty ? '<option value="">-</option>' : "";
            select.innerHTML = empty + numericFields.map((field) =>
              `<option value="${{field}}">${{formatFieldLabel(field)}}</option>`
            ).join("");
          }};

          selectField("field_select", false);
          selectField("field_select_2", true);
          selectField("field_select_y", true);
          const defaultField = numericFields.find((field) => field.includes("data.bat") || field.includes("bat")) || numericFields[0] || "";
          const fieldSelect = document.getElementById("field_select");
          if (fieldSelect && defaultField) fieldSelect.value = defaultField;
          updateMapPortOptions();
          updateTimeBounds({{
            portValue: document.getElementById("port_filter")?.value.trim() || "",
            startId: "start_time",
            endId: "end_time",
            requireLocation: false
          }});
          updateTimeBounds({{
            portValue: document.getElementById("map_port_filter")?.value || "",
            startId: "map_start_time",
            endId: "map_end_time",
            requireLocation: true
          }});

          let currentTable = {{ columns: [], rows: [] }};
          let currentMapRows = [];
          let chartRef = null;
          let chartShowPoints = true;
          let chartShowLine = true;
          const setDebug = () => {{}};

          renderMessageSummary();

          const parseLocalInput = (id) => {{
            const input = document.getElementById(id);
            if (!input || !input.value) return null;
            const parsed = Date.parse(input.value);
            return Number.isFinite(parsed) ? parsed : null;
          }};

          function formatLocalDateTime(ms) {{
            const date = new Date(ms);
            const pad = (value) => String(value).padStart(2, "0");
            return `${{date.getFullYear()}}-${{pad(date.getMonth() + 1)}}-${{pad(date.getDate())}}T${{pad(date.getHours())}}:${{pad(date.getMinutes())}}`;
          }}

          function updateTimeBounds(opts) {{
            const {{ portValue, startId, endId, requireLocation }} = opts;
            const latField = requireLocation ? pickBestLat() : "";
            const lonField = requireLocation ? pickBestLon() : "";
            const ignoreZero = requireLocation ? document.getElementById("ignore_zero_coords")?.checked || false : false;
            let minTs = null;
            let maxTs = null;
            records.forEach((record) => {{
              if (portValue && String(record.fport) !== String(portValue)) return;
              if (requireLocation) {{
                if (!latField || !lonField) return;
                const lat = numericValue(record, latField);
                const lon = numericValue(record, lonField);
                if (lat === null || lon === null) return;
                if (ignoreZero && (lat === 0 || lon === 0)) return;
                if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return;
              }}
              if (!record.timestamp) return;
              if (minTs === null || record.timestamp < minTs) minTs = record.timestamp;
              if (maxTs === null || record.timestamp > maxTs) maxTs = record.timestamp;
            }});
            if (minTs === null || maxTs === null) return;
            const startInput = document.getElementById(startId);
            const endInput = document.getElementById(endId);
            if (startInput) startInput.value = formatLocalDateTime(minTs);
            if (endInput) endInput.value = formatLocalDateTime(maxTs);
          }}

          const filterRecords = (list, filters) => {{
            return list.filter((record) => {{
              if (filters.port && String(record.fport) !== String(filters.port)) return false;
              if (filters.start && (!record.timestamp || record.timestamp < filters.start)) return false;
              if (filters.end && (!record.timestamp || record.timestamp > filters.end)) return false;
              return true;
            }});
          }};

          function numericValue(record, field) {{
            if (!field) return null;
            const value = record.flat[field];
            return parseNumber(value);
          }}

          const aggValue = (values, agg) => {{
            if (!values.length) return null;
            const sorted = values.slice().sort((a, b) => a - b);
            const sum = values.reduce((acc, val) => acc + val, 0);
            switch (agg) {{
              case "min":
                return sorted[0];
              case "max":
                return sorted[sorted.length - 1];
              case "sum":
                return sum;
              case "count":
                return values.length;
              case "median":
                return sorted.length % 2
                  ? sorted[(sorted.length - 1) / 2]
                  : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;
              case "stdev": {{
                const mean = sum / values.length;
                const variance = values.reduce((acc, val) => acc + (val - mean) ** 2, 0) / (values.length || 1);
                return Math.sqrt(variance);
              }}
              case "mean":
              default:
                return sum / values.length;
            }}
          }};

          const bucketTime = (ms, bucket) => {{
            const date = new Date(ms);
            if (bucket === "minute") {{
              date.setSeconds(0, 0);
            }} else if (bucket === "hour") {{
              date.setMinutes(0, 0, 0);
            }} else if (bucket === "day") {{
              date.setHours(0, 0, 0, 0);
            }}
            return date.getTime();
          }};

          const setStatsBox = (values, field) => {{
            const box = document.getElementById("stats_box");
            const summary = document.getElementById("stats_summary");
            if (!box) return;
            if (!values.length) {{
              if (summary) summary.textContent = "Statistics";
              box.innerHTML = "<div class=\\"analytics-hint\\">No data for statistics.</div>";
              return;
            }}
            if (summary) summary.textContent = `Statistics for ${{formatFieldLabel(field)}}`;
            const sorted = values.slice().sort((a, b) => a - b);
            const count = values.length;
            const mean = values.reduce((acc, val) => acc + val, 0) / count;
            const median = count % 2
              ? sorted[(count - 1) / 2]
              : (sorted[count / 2 - 1] + sorted[count / 2]) / 2;
            const p5 = sorted[Math.floor(count * 0.05)];
            const p95 = sorted[Math.floor(count * 0.95)];
            const variance = values.reduce((acc, val) => acc + (val - mean) ** 2, 0) / (count || 1);
            const stdev = Math.sqrt(variance);
            box.innerHTML = `
              <div class="analysis-table-wrapper" style="margin-top:0.4rem;">
                <table class="analysis-table">
                  <tbody>
                    <tr><td>N</td><td>${{count}}</td></tr>
                    <tr><td>Min</td><td>${{formatValue(field, sorted[0])}}</td></tr>
                    <tr><td>P5</td><td>${{formatValue(field, p5)}}</td></tr>
                    <tr><td>Median</td><td>${{formatValue(field, median)}}</td></tr>
                    <tr><td>Average</td><td>${{formatValue(field, mean)}}</td></tr>
                    <tr><td>P95</td><td>${{formatValue(field, p95)}}</td></tr>
                    <tr><td>Max</td><td>${{formatValue(field, sorted[sorted.length - 1])}}</td></tr>
                    <tr><td>Std.dev.</td><td>${{formatValue(field, stdev)}}</td></tr>
                  </tbody>
                </table>
              </div>
            `;
          }};

          const renderTable = (columns, rows) => {{
            currentTable = {{ columns, rows }};
            const head = document.getElementById("analysis_table_head");
            const body = document.getElementById("analysis_table_body");
            if (!head || !body) return;
            head.innerHTML = columns.map((col) => `<th>${{col}}</th>`).join("");
            body.innerHTML = rows.map((row) => {{
              const tds = columns.map((col) => `<td>${{row[col] ?? ""}}</td>`).join("");
              return `<tr>${{tds}}</tr>`;
            }}).join("");
          }};

          const chartCanvas = () => document.getElementById("chart_canvas");
          const chartError = (message) => {{
            const banner = document.getElementById("analysis_error");
            if (banner) {{
              banner.textContent = message;
              banner.style.display = "block";
            }}
          }};
          const resetChart = () => {{
            if (chartRef) {{
              chartRef.destroy();
              chartRef = null;
            }}
          }};

          const showEmptyChart = () => {{
            resetChart();
            const canvas = chartCanvas();
            if (!canvas) return;
            const ctx = canvas.getContext("2d");
            const width = canvas.clientWidth || 800;
            const height = canvas.clientHeight || 320;
            canvas.width = width;
            canvas.height = height;
            ctx.clearRect(0, 0, width, height);
            ctx.fillStyle = "#94a3b8";
            ctx.font = "14px sans-serif";
            ctx.fillText("No data for chart.", 24, height / 2);
          }};

          const chooseTimeUnit = (points) => {{
            if (!points || !points.length) return "hour";
            const sorted = points.slice().sort((a, b) => a.x - b.x);
            const span = sorted[sorted.length - 1].x - sorted[0].x;
            const day = 24 * 60 * 60 * 1000;
            if (span < 2 * 60 * 60 * 1000) return "minute";
            if (span < 2 * day) return "hour";
            return "day";
          }};

          const formatTimeLabel = (value) => {{
            const num = parseNumber(value);
            if (num === null) return "";
            const date = new Date(num);
            if (Number.isNaN(date.getTime())) return "";
            return date.toLocaleString(undefined, {{
              month: "short",
              day: "2-digit",
              hour: "2-digit",
              minute: "2-digit"
            }});
          }};

          const getTimeAxisConfig = (points) => {{
            if (!points.length) {{
              return {{ min: undefined, max: undefined, stepSize: undefined, maxTicks: 12 }};
            }}
            const xs = points.map((point) => point.x).filter((x) => Number.isFinite(x));
            const min = Math.min(...xs);
            const max = Math.max(...xs);
            const span = Math.max(1, max - min);
            const hour = 60 * 60 * 1000;
            const day = 24 * hour;
            let stepSize = hour;
            if (span <= 6 * hour) stepSize = hour;
            else if (span <= day) stepSize = 2 * hour;
            else if (span <= 3 * day) stepSize = 6 * hour;
            else if (span <= 7 * day) stepSize = 12 * hour;
            else stepSize = day;
            const minAligned = Math.floor(min / stepSize) * stepSize;
            const maxAligned = Math.ceil(max / stepSize) * stepSize;
            return {{ min: minAligned, max: maxAligned, stepSize, maxTicks: 14 }};
          }};

          const getZoomPluginConfig = () => {{
            return {{
              zoom: {{
                zoom: {{
                  drag: {{
                    enabled: true,
                    backgroundColor: "rgba(37,99,235,0.12)",
                    borderColor: "rgba(37,99,235,0.6)",
                    borderWidth: 1
                  }},
                  mode: "x",
                  onZoomComplete: ({{ chart }}) => {{
                    const scale = chart.scales?.x;
                    if (!scale) return;
                    const start = scale.min;
                    const end = scale.max;
                    if (!Number.isFinite(start) || !Number.isFinite(end)) return;
                    const startInput = document.getElementById("start_time");
                    const endInput = document.getElementById("end_time");
                    if (startInput) startInput.value = formatLocalDateTime(start);
                    if (endInput) endInput.value = formatLocalDateTime(end);
                    generateAnalysis();
                  }}
                }}
              }}
            }};
          }};

          const timeScaleType = () => {{
            return "linear";
          }};

          const renderLine = (points, config) => {{
            if (!points.length) return showEmptyChart();
            resetChart();
            const ctx = chartCanvas()?.getContext("2d");
            if (!ctx || !window.Chart) {{
              chartError("Chart library not loaded. Ensure Chart.js is reachable.");
              setDebug(`Chart.js available: ${{!!window.Chart}}`);
              return;
            }}
            const xScaleType = timeScaleType();
            const timeAxis = getTimeAxisConfig(points);
            try {{
              chartRef = new Chart(ctx, {{
                type: "line",
                data: {{
                  datasets: [
                    {{
                      label: config.label || config.yLabel || "Series",
                      data: points,
                      borderColor: "#2563eb",
                      backgroundColor: "rgba(37,99,235,0.15)",
                      pointRadius: chartShowPoints ? 2 : 0,
                      showLine: chartShowLine,
                      borderWidth: 2,
                      parsing: false
                    }}
                  ]
                }},
                options: {{
                  responsive: true,
                  maintainAspectRatio: false,
                  interaction: {{ mode: "nearest", intersect: false }},
                  scales: {{
                    x: {{
                      type: xScaleType,
                      title: {{ display: !!config.xLabel, text: config.xLabel }},
                      ticks: {{
                        stepSize: timeAxis.stepSize,
                        maxTicksLimit: timeAxis.maxTicks,
                        callback: (value) => formatTimeLabel(value)
                      }},
                      min: timeAxis.min,
                      max: timeAxis.max
                    }},
                    y: {{ title: {{ display: !!config.yLabel, text: config.yLabel }} }}
                  }},
                  plugins: {{
                    legend: {{ position: "bottom" }},
                    title: {{ display: !!config.title, text: config.title }},
                    ...getZoomPluginConfig(),
                    tooltip: {{
                      callbacks: {{
                        title: (items) => {{
                          const x = items[0]?.parsed?.x;
                          return Number.isFinite(x) ? formatTimeLabel(x) : "";
                        }},
                        label: (ctx) => {{
                          const field = config.field || "";
                          const value = ctx.parsed?.y;
                          const label = ctx.dataset?.label || "";
                          return label ? `${{label}}: ${{formatValue(field, value)}}` : formatValue(field, value);
                        }}
                      }}
                    }}
                  }}
                }}
              }});
              setDebug(`Chart type=line, points=${{points.length}}, xScale=${{xScaleType}}`);
            }} catch (err) {{
              chartError(`Chart render failed: ${{err && err.message ? err.message : err}}`);
              setDebug(`Chart error: ${{err && err.message ? err.message : err}}`);
            }}
          }};

          const renderLineMulti = (series, config) => {{
            const points = series.flatMap((line) => line.points || []);
            if (!points.length) return showEmptyChart();
            resetChart();
            const ctx = chartCanvas()?.getContext("2d");
            if (!ctx || !window.Chart) {{
              chartError("Chart library not loaded. Ensure Chart.js is reachable.");
              setDebug(`Chart.js available: ${{!!window.Chart}}`);
              return;
            }}
            const xScaleType = timeScaleType();
            const timeAxis = getTimeAxisConfig(points);
            const hasSecondaryAxis = series.length > 1 && !!config.y2Label;
            const datasets = series.map((line, index) => ({{
              label: line.label || `Series ${{index + 1}}`,
              data: line.points || [],
              borderColor: line.color || (index === 0 ? "#2563eb" : "#dc2626"),
              backgroundColor: "transparent",
              pointRadius: chartShowPoints ? 2 : 0,
              showLine: chartShowLine,
              borderWidth: 2,
              parsing: false,
              field: line.field || "",
              yAxisID: hasSecondaryAxis && index === 1 ? "y1" : "y"
            }}));
            try {{
              chartRef = new Chart(ctx, {{
                type: "line",
                data: {{ datasets }},
                options: {{
                  responsive: true,
                  maintainAspectRatio: false,
                  interaction: {{ mode: "nearest", intersect: false }},
                  scales: {{
                    x: {{
                      type: xScaleType,
                      title: {{ display: !!config.xLabel, text: config.xLabel }},
                      ticks: {{
                        stepSize: timeAxis.stepSize,
                        maxTicksLimit: timeAxis.maxTicks,
                        callback: (value) => formatTimeLabel(value)
                      }},
                      min: timeAxis.min,
                      max: timeAxis.max
                    }},
                    y: {{ title: {{ display: !!config.yLabel, text: config.yLabel }} }},
                    y1: hasSecondaryAxis
                      ? {{
                          position: "right",
                          title: {{ display: true, text: config.y2Label }},
                          grid: {{ drawOnChartArea: false }}
                        }}
                      : {{ display: false }}
                  }},
                  plugins: {{
                    legend: {{ position: "bottom" }},
                    title: {{ display: !!config.title, text: config.title }},
                    ...getZoomPluginConfig(),
                    tooltip: {{
                      callbacks: {{
                        title: (items) => {{
                          const x = items[0]?.parsed?.x;
                          return Number.isFinite(x) ? formatTimeLabel(x) : "";
                        }},
                        label: (ctx) => {{
                          const field = ctx.dataset?.field || config.field || "";
                          const value = ctx.parsed?.y;
                          const label = ctx.dataset?.label || "";
                          return label ? `${{label}}: ${{formatValue(field, value)}}` : formatValue(field, value);
                        }}
                      }}
                    }}
                  }}
                }}
              }});
              setDebug(`Chart type=multi-line, series=${{series.length}}, points=${{points.length}}, xScale=${{xScaleType}}`);
            }} catch (err) {{
              chartError(`Chart render failed: ${{err && err.message ? err.message : err}}`);
              setDebug(`Chart error: ${{err && err.message ? err.message : err}}`);
            }}
          }};

          const renderBar = (points, config) => {{
            if (!points.length) return showEmptyChart();
            resetChart();
            const ctx = chartCanvas()?.getContext("2d");
            if (!ctx || !window.Chart) {{
              chartError("Chart library not loaded. Ensure Chart.js is reachable.");
              setDebug(`Chart.js available: ${{!!window.Chart}}`);
              return;
            }}
            const xScaleType = timeScaleType();
            const timeAxis = getTimeAxisConfig(points);
            try {{
              chartRef = new Chart(ctx, {{
                type: "bar",
                data: {{
                  datasets: [
                    {{
                      label: config.label || config.yLabel || "Series",
                      data: points,
                      backgroundColor: "rgba(37,99,235,0.65)",
                      parsing: false
                    }}
                  ]
                }},
                options: {{
                  responsive: true,
                  maintainAspectRatio: false,
                  interaction: {{ mode: "nearest", intersect: false }},
                  scales: {{
                    x: {{
                      type: xScaleType,
                      title: {{ display: !!config.xLabel, text: config.xLabel }},
                      ticks: {{
                        stepSize: timeAxis.stepSize,
                        maxTicksLimit: timeAxis.maxTicks,
                        callback: (value) => formatTimeLabel(value)
                      }},
                      min: timeAxis.min,
                      max: timeAxis.max
                    }},
                    y: {{ title: {{ display: !!config.yLabel, text: config.yLabel }} }}
                  }},
                  plugins: {{
                    legend: {{ position: "bottom" }},
                    title: {{ display: !!config.title, text: config.title }},
                    ...getZoomPluginConfig(),
                    tooltip: {{
                      callbacks: {{
                        title: (items) => {{
                          const x = items[0]?.parsed?.x;
                          return Number.isFinite(x) ? formatTimeLabel(x) : "";
                        }},
                        label: (ctx) => {{
                          const field = config.field || "";
                          const value = ctx.parsed?.y;
                          const label = ctx.dataset?.label || "";
                          return label ? `${{label}}: ${{formatValue(field, value)}}` : formatValue(field, value);
                        }}
                      }}
                    }}
                  }}
                }}
              }});
              setDebug(`Chart type=bar, points=${{points.length}}, xScale=${{xScaleType}}`);
            }} catch (err) {{
              chartError(`Chart render failed: ${{err && err.message ? err.message : err}}`);
              setDebug(`Chart error: ${{err && err.message ? err.message : err}}`);
            }}
          }};

          const renderScatter = (points, config) => {{
            if (!points.length) return showEmptyChart();
            resetChart();
            const ctx = chartCanvas()?.getContext("2d");
            if (!ctx || !window.Chart) {{
              chartError("Chart library not loaded. Ensure Chart.js is reachable.");
              setDebug(`Chart.js available: ${{!!window.Chart}}`);
              return;
            }}
            chartRef = new Chart(ctx, {{
              type: "scatter",
              data: {{
                datasets: [
                  {{
                    label: config.label || "Scatter",
                    data: points,
                    borderColor: "#2563eb",
                    backgroundColor: "rgba(37,99,235,0.4)",
                    parsing: false
                  }}
                ]
              }},
              options: {{
                responsive: true,
                maintainAspectRatio: false,
                interaction: {{ mode: "nearest", intersect: false }},
                scales: {{
                  x: {{ type: "linear", title: {{ display: !!config.xLabel, text: config.xLabel }} }},
                  y: {{ title: {{ display: !!config.yLabel, text: config.yLabel }} }}
                }},
                plugins: {{
                  legend: {{ position: "bottom" }},
                  title: {{ display: !!config.title, text: config.title }},
                  tooltip: {{
                    callbacks: {{
                      label: (ctx) => {{
                        const x = ctx.parsed?.x;
                        const y = ctx.parsed?.y;
                        const xLabel = formatValue(config.xField || "", x);
                        const yLabel = formatValue(config.yField || "", y);
                        return `x: ${{xLabel}}  y: ${{yLabel}}`;
                      }}
                    }}
                  }}
                }}
              }}
            }});
            setDebug(`Chart type=scatter, points=${{points.length}}`);
          }};

          const renderHistogram = (values, field) => {{
            const count = values.length;
            if (!count) {{
              renderTable([], []);
              showEmptyChart();
              return;
            }}
            const min = Math.min(...values);
            const max = Math.max(...values);
            const bins = Math.min(40, Math.max(8, Math.ceil(Math.sqrt(count))));
            const width = (max - min) / (bins || 1);
            const counts = new Array(bins).fill(0);
            values.forEach((value) => {{
              const idx = width ? Math.min(bins - 1, Math.max(0, Math.floor((value - min) / width))) : 0;
              counts[idx] += 1;
            }});
            const tableRows = counts.map((count, idx) => {{
              const start = min + idx * width;
              const end = start + width;
              return {{
                "Bin": `${{formatNumber(start, getPrecision(field))}}-${{formatNumber(end, getPrecision(field))}}`,
                "Count": count
              }};
            }});
            renderTable(["Bin", "Count"], tableRows);
            resetChart();
            const ctx = chartCanvas()?.getContext("2d");
            if (!ctx || !window.Chart) return;
            chartRef = new Chart(ctx, {{
              type: "bar",
              data: {{
                labels: tableRows.map((row) => row["Bin"]),
                datasets: [
                  {{
                    label: "Count",
                    data: counts,
                    backgroundColor: "rgba(37,99,235,0.65)"
                  }}
                ]
              }},
              options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                  legend: {{ position: "bottom" }},
                  title: {{ display: true, text: `Distribution of ${{formatFieldLabel(field)}}` }}
                }}
              }}
            }});
            setDebug(`Chart type=histogram, bins=${{counts.length}}`);
          }};

          const updateOutlierUI = () => {{
            const chartType = document.getElementById("chart_type")?.value || "line";
            const fieldY = document.getElementById("field_select_y")?.value || "";
            const wrap = document.getElementById("outlier_y_wrap");
            if (wrap) {{
              wrap.style.display = chartType === "scatter" && fieldY ? "block" : "none";
            }}
            const secondField = document.getElementById("field_select_2");
            if (secondField) {{
              const row = secondField.closest(".control-row");
              if (row) row.style.display = chartType === "line" ? "flex" : "none";
            }}
          }};

          const renderDefaultMap = () => {{
            const mapPanel = document.getElementById("map_panel");
            if (!mapPanel) return;
            mapPanel.style.display = "none";
            mapPanel.innerHTML = "";
          }};

          const setAnalyticsPanelsVisible = (visible) => {{
            const statsPanel = document.getElementById("stats_panel");
            const chartPanel = document.getElementById("chart_panel");
            const tablePanel = document.getElementById("analysis_table_panel");
            const display = visible ? "" : "none";
            if (statsPanel) statsPanel.style.display = display;
            if (chartPanel) chartPanel.style.display = display;
            if (tablePanel) tablePanel.style.display = display;
          }};

          let leafletPromise = null;
          let heatPromise = null;
          const loadLeaflet = () => {{
            if (window.L) return Promise.resolve();
            if (leafletPromise) return leafletPromise;
            const loadCss = (href, integrity) => {{
              const link = document.createElement("link");
              link.rel = "stylesheet";
              link.href = href;
              if (integrity) link.integrity = integrity;
              link.crossOrigin = "";
              link.setAttribute("data-leaflet", "true");
              document.head.appendChild(link);
            }};
            const loadScript = (src, integrity) => new Promise((resolve, reject) => {{
              const script = document.createElement("script");
              script.src = src;
              if (integrity) script.integrity = integrity;
              script.crossOrigin = "";
              script.onload = () => resolve();
              script.onerror = () => reject(new Error("Failed to load map library."));
              document.body.appendChild(script);
            }});
            const loadHeat = () => {{
              if (window.L && window.L.heatLayer) return Promise.resolve();
              if (heatPromise) return heatPromise;
              heatPromise = loadScript(
                "https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"
              );
              return heatPromise;
            }};
            leafletPromise = (async () => {{
              loadCss(
                "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css",
                "sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
              );
              try {{
                await loadScript(
                  "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js",
                  "sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
                );
                try {{
                  await loadHeat();
                }} catch (err) {{
                  // Heat map is optional; ignore load failures.
                }}
                return;
              }} catch (err) {{
                loadCss(
                  "https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css",
                  "sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
                );
                await loadScript(
                  "https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js",
                  "sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo="
                );
              }}
            }})();
            return leafletPromise;
          }};

          function updateMapPortOptions() {{
            const select = document.getElementById("map_port_filter");
            if (!select) return;
            const latField = pickBestLat();
            const lonField = pickBestLon();
            const ignoreZero = document.getElementById("ignore_zero_coords")?.checked || false;
            const options = new Map();
            records.forEach((record) => {{
              const lat = numericValue(record, latField);
              const lon = numericValue(record, lonField);
              if (lat === null || lon === null) return;
              if (ignoreZero && (lat === 0 || lon === 0)) return;
              if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return;
              const port = record.fport;
              if (port === undefined || port === null) return;
              const portNumber = Number(port);
              const key = Number.isFinite(portNumber) ? portNumber : port;
              if (options.has(key)) return;
              options.set(key, resolveMessageType(portNumber, record.flat || {{}}));
            }});
            const previous = select.value;
            const entries = Array.from(options.entries()).sort((a, b) => a[0] - b[0]);
            select.innerHTML = `<option value="">All ports</option>` + entries.map(([port, type]) =>
              `<option value="${{port}}">Port ${{port}} (${{type}})</option>`
            ).join("");
            if (previous && select.querySelector(`option[value="${{previous}}"]`)) {{
              select.value = previous;
            }}
          }}

          const resetOutlierRanges = () => {{
            const minX = document.getElementById("min_x");
            const maxX = document.getElementById("max_x");
            const minY = document.getElementById("min_y");
            const maxY = document.getElementById("max_y");
            if (minX) minX.value = "";
            if (maxX) maxX.value = "";
            if (minY) minY.value = "";
            if (maxY) maxY.value = "";
            const hintX = document.getElementById("x_range_hint");
            const hintY = document.getElementById("y_range_hint");
            if (hintX) hintX.textContent = "";
            if (hintY) hintY.textContent = "";
          }};

          const generateAnalysis = () => {{
            updateOutlierUI();
            setAnalyticsPanelsVisible(true);
            const fieldX = document.getElementById("field_select")?.value || "";
            const field2 = document.getElementById("field_select_2")?.value || "";
            const fieldY = document.getElementById("field_select_y")?.value || "";
            const bucket = document.getElementById("bucket_select")?.value || "none";
            const agg = document.getElementById("agg_select")?.value || "mean";
            const chartType = document.getElementById("chart_type")?.value || "line";
            const filters = {{
              port: document.getElementById("port_filter")?.value.trim() || "",
              start: parseLocalInput("start_time"),
              end: parseLocalInput("end_time")
            }};
            let filtered = filterRecords(records, filters);
            const valuesX = filtered.map((record) => numericValue(record, fieldX)).filter((v) => v !== null);
            const valuesY = filtered.map((record) => numericValue(record, fieldY)).filter((v) => v !== null);

            const minXInput = document.getElementById("min_x");
            const maxXInput = document.getElementById("max_x");
            const minYInput = document.getElementById("min_y");
            const maxYInput = document.getElementById("max_y");

            const applyRange = (values, minInput, maxInput, hintId, field) => {{
              if (!minInput || !maxInput) return {{ min: null, max: null }};
              const minVal = parseNumber(minInput.value);
              const maxVal = parseNumber(maxInput.value);
              if (minVal === null || maxVal === null) {{
                if (values.length) {{
                  const min = Math.min(...values);
                  const max = Math.max(...values);
                  minInput.value = String(min);
                  maxInput.value = String(max);
                  const hint = document.getElementById(hintId);
                  if (hint) {{
                    hint.textContent = `auto range from data: [${{formatNumber(min, getPrecision(field))}}, ${{formatNumber(max, getPrecision(field))}}]`;
                  }}
                  return {{ min, max }};
                }}
                const hint = document.getElementById(hintId);
                if (hint) hint.textContent = "no numeric values found";
                return {{ min: null, max: null }};
              }}
              return {{ min: minVal, max: maxVal }};
            }};

            const xRange = applyRange(valuesX, minXInput, maxXInput, "x_range_hint", fieldX);
            const yRange = chartType === "scatter" && fieldY
              ? applyRange(valuesY, minYInput, maxYInput, "y_range_hint", fieldY)
              : {{ min: null, max: null }};

            filtered = filtered.filter((record) => {{
              const vx = numericValue(record, fieldX);
              if (vx === null) return false;
              if (xRange.min !== null && vx < xRange.min) return false;
              if (xRange.max !== null && vx > xRange.max) return false;
              if (chartType === "scatter" && fieldY) {{
                const vy = numericValue(record, fieldY);
                if (vy === null) return false;
                if (yRange.min !== null && vy < yRange.min) return false;
                if (yRange.max !== null && vy > yRange.max) return false;
              }}
              return true;
            }});

            setStatsBox(filtered.map((record) => numericValue(record, fieldX)).filter((v) => v !== null), fieldX);

            if (chartType === "scatter" && fieldY) {{
              const points = filtered.map((record) => {{
                const x = numericValue(record, fieldX);
                const y = numericValue(record, fieldY);
                return x !== null && y !== null ? {{ x, y, timestamp: record.timestamp }} : null;
              }}).filter(Boolean);
              const tableRows = points.map((point) => ({{
                "Timestamp": point.timestamp ? new Date(point.timestamp).toLocaleString() : "",
                [formatFieldLabel(fieldX)]: formatValue(fieldX, point.x),
                [formatFieldLabel(fieldY)]: formatValue(fieldY, point.y)
              }}));
              renderTable(["Timestamp", formatFieldLabel(fieldX), formatFieldLabel(fieldY)], tableRows);
              renderScatter(points, {{
                xLabel: formatFieldLabel(fieldX),
                yLabel: formatFieldLabel(fieldY),
                title: `${{formatFieldLabel(fieldY)}} vs ${{formatFieldLabel(fieldX)}}`,
                xField: fieldX,
                yField: fieldY
              }});
              return;
            }}

            if (chartType === "hist") {{
              renderHistogram(filtered.map((record) => numericValue(record, fieldX)).filter((v) => v !== null), fieldX);
              return;
            }}

            if (bucket === "none") {{
              const points = filtered
                .map((record) => {{
                  if (!record.timestamp) return null;
                  const value = numericValue(record, fieldX);
                  return value !== null ? {{ x: record.timestamp, y: value }} : null;
                }})
                .filter(Boolean)
                .sort((a, b) => a.x - b.x);
              let points2 = [];
              if (field2) {{
                points2 = filtered
                  .map((record) => {{
                    if (!record.timestamp) return null;
                    const value = numericValue(record, field2);
                    return value !== null ? {{ x: record.timestamp, y: value }} : null;
                  }})
                  .filter(Boolean)
                  .sort((a, b) => a.x - b.x);
              }}
              const points2Map = new Map(points2.map((point) => [point.x, point.y]));
              const rowsOut = points.map((point) => {{
                const row = {{
                  "Timestamp": new Date(point.x).toLocaleString(),
                  [formatFieldLabel(fieldX)]: formatValue(fieldX, point.y)
                }};
                if (field2 && points2Map.has(point.x)) {{
                  row[formatFieldLabel(field2)] = formatValue(field2, points2Map.get(point.x));
                }}
                return row;
              }});
              const columns = ["Timestamp", formatFieldLabel(fieldX)];
              if (field2) columns.push(formatFieldLabel(field2));
              renderTable(columns, rowsOut);
              if (chartType === "bar") {{
                renderBar(points, {{
                  xLabel: "Time",
                  yLabel: formatFieldLabel(fieldX),
                  title: `${{formatFieldLabel(fieldX)}} over time`,
                  field: fieldX
                }});
              }} else if (field2 && points2.length) {{
                renderLineMulti(
                  [
                    {{ label: formatFieldLabel(fieldX), points, field: fieldX }},
                    {{ label: formatFieldLabel(field2), points: points2, field: field2 }}
                  ],
                  {{
                    xLabel: "Time",
                    yLabel: formatFieldLabel(fieldX),
                    y2Label: formatFieldLabel(field2),
                    title: `${{formatFieldLabel(fieldX)}} & ${{formatFieldLabel(field2)}} over time`,
                    field: fieldX
                  }}
                );
              }} else {{
                renderLine(points, {{
                  xLabel: "Time",
                  yLabel: formatFieldLabel(fieldX),
                  title: `${{formatFieldLabel(fieldX)}} over time`,
                  field: fieldX
                }});
              }}
              return;
            }}

            const buckets = new Map();
            const buckets2 = new Map();
            filtered.forEach((record) => {{
              if (!record.timestamp) return;
              const bucketKey = bucketTime(record.timestamp, bucket);
              const value = numericValue(record, fieldX);
              if (value !== null) {{
                if (!buckets.has(bucketKey)) buckets.set(bucketKey, []);
                buckets.get(bucketKey).push(value);
              }}
              if (field2) {{
                const value2 = numericValue(record, field2);
                if (value2 !== null) {{
                  if (!buckets2.has(bucketKey)) buckets2.set(bucketKey, []);
                  buckets2.get(bucketKey).push(value2);
                }}
              }}
            }});

            const points = Array.from(buckets.entries())
              .map(([key, values]) => ({{ x: key, y: aggValue(values, agg) }}))
              .filter((point) => point.y !== null)
              .sort((a, b) => a.x - b.x);
            const points2 = field2
              ? Array.from(buckets2.entries())
                  .map(([key, values]) => ({{ x: key, y: aggValue(values, agg) }}))
                  .filter((point) => point.y !== null)
                  .sort((a, b) => a.x - b.x)
              : [];

            const points2Map = new Map(points2.map((point) => [point.x, point.y]));
            const rowsOut = points.map((point) => {{
              const row = {{
                "Bucket start": new Date(point.x).toLocaleString(),
                [formatFieldLabel(fieldX)]: formatValue(fieldX, point.y)
              }};
              if (field2 && points2Map.has(point.x)) {{
                row[formatFieldLabel(field2)] = formatValue(field2, points2Map.get(point.x));
              }}
              return row;
            }});
            const columns = ["Bucket start", formatFieldLabel(fieldX)];
            if (field2) columns.push(formatFieldLabel(field2));
            renderTable(columns, rowsOut);
            if (chartType === "bar") {{
              renderBar(points, {{
                xLabel: `Time (${{bucket}})`,
                yLabel: formatFieldLabel(fieldX),
                title: `${{formatFieldLabel(fieldX)}} per ${{bucket}}`,
                field: fieldX
              }});
            }} else if (field2 && points2.length) {{
              renderLineMulti(
                [
                  {{ label: formatFieldLabel(fieldX), points, field: fieldX }},
                  {{ label: formatFieldLabel(field2), points: points2, field: field2 }}
                ],
                {{
                  xLabel: `Time (${{bucket}})`,
                  yLabel: formatFieldLabel(fieldX),
                  y2Label: formatFieldLabel(field2),
                  title: `${{formatFieldLabel(fieldX)}} & ${{formatFieldLabel(field2)}} per ${{bucket}}`,
                  field: fieldX
                }}
              );
            }} else {{
              renderLine(points, {{
                xLabel: `Time (${{bucket}})`,
                yLabel: formatFieldLabel(fieldX),
                title: `${{formatFieldLabel(fieldX)}} per ${{bucket}}`,
                field: fieldX
              }});
            }}
          }};

          const updateChartToggleButtons = () => {{
            const lineButton = document.getElementById("chart_toggle_line");
            const pointButton = document.getElementById("chart_toggle_points");
            const chartType = document.getElementById("chart_type")?.value || "line";
            const showLineControls = chartType === "line";
            const display = showLineControls ? "" : "none";
            if (lineButton) {{
              lineButton.style.display = display;
              lineButton.classList.toggle("is-active", chartShowLine);
            }}
            if (pointButton) {{
              pointButton.style.display = display;
              pointButton.classList.toggle("is-active", chartShowPoints);
            }}
          }};

          const toggleChartExpand = () => {{
            const chartPanel = document.getElementById("chart_panel");
            const button = document.getElementById("chart_expand");
            if (!chartPanel || !button) return;
            const isExpanded = chartPanel.classList.toggle("chart-expanded");
            button.innerHTML = isExpanded
              ? '<span class="material-icons" aria-hidden="true">close_fullscreen</span>'
              : '<span class="material-icons" aria-hidden="true">open_in_full</span>';
            button.title = isExpanded ? "Collapse chart" : "Expand chart";
            button.setAttribute("aria-label", button.title);
            if (chartRef) {{
              setTimeout(() => chartRef.resize(), 60);
            }}
          }};

          const resetChartZoom = () => {{
            if (chartRef && chartRef.resetZoom) {{
              chartRef.resetZoom();
            }}
            updateTimeBounds({{
              portValue: document.getElementById("port_filter")?.value.trim() || "",
              startId: "start_time",
              endId: "end_time",
              requireLocation: false
            }});
            generateAnalysis();
          }};

          const toggleChartLine = () => {{
            chartShowLine = !chartShowLine;
            updateChartToggleButtons();
            generateAnalysis();
          }};

          const toggleChartPoints = () => {{
            chartShowPoints = !chartShowPoints;
            updateChartToggleButtons();
            generateAnalysis();
          }};

          let mapRef = null;
          let mapLayer = null;
          let mapTrack = null;
          let mapLegend = null;
          let mapTrackEnabled = false;
          let mapMarkersEnabled = true;
          let mapHeatEnabled = false;
          let mapSatelliteEnabled = false;
          let mapHeatLayer = null;
          let mapTileLayer = null;
          const generateMap = async () => {{
            const mapPanel = document.getElementById("map_panel");
            const mapMessage = document.getElementById("map_message");
            if (!mapPanel) return;
            if (mapMessage) mapMessage.textContent = "";
            mapPanel.style.display = "";
            updateMapPortOptions();
            const filters = {{
              port: document.getElementById("map_port_filter")?.value.trim() || "",
              start: parseLocalInput("map_start_time"),
              end: parseLocalInput("map_end_time")
            }};
            const latField = pickBestLat();
            const lonField = pickBestLon();
            const ignoreZero = document.getElementById("ignore_zero_coords")?.checked || false;
            const track = mapTrackEnabled;

            if (!latField || !lonField) {{
              if (mapMessage) {{
                mapMessage.textContent = "This decoded file does not include location fields to display a map.";
              }}
              mapPanel.style.display = "none";
              const controls = document.querySelector(".map-controls");
              if (controls) controls.style.display = "none";
              renderTableHead("map_table_head", []);
              renderTableBody("map_table_body", [], []);
              if (document.getElementById("map_stats")) {{
                document.getElementById("map_stats").innerHTML = "";
              }}
              if (mapLayer) mapLayer.clearLayers();
              if (mapTrack) {{
                mapTrack.remove();
                mapTrack = null;
              }}
              if (mapHeatLayer) {{
                mapHeatLayer.remove();
                mapHeatLayer = null;
              }}
              if (mapLegend) {{
                mapLegend.remove();
                mapLegend = null;
              }}
              return;
            }}

            const controls = document.querySelector(".map-controls");
            if (controls) controls.style.display = "";

            let filtered = filterRecords(records, filters);
            const points = filtered.map((record) => {{
              const lat = numericValue(record, latField);
              const lon = numericValue(record, lonField);
              if (lat === null || lon === null) return null;
              if (ignoreZero && (lat === 0 || lon === 0)) return null;
              if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return null;
              return {{ lat, lon, timestamp: record.timestamp }};
            }}).filter(Boolean);

            if (!points.length) {{
              if (mapMessage) {{
                mapMessage.textContent = "This decoded file does not contain usable location data to plot on the map.";
              }}
              mapPanel.style.display = "none";
              currentMapRows = [];
              renderTableHead("map_table_head", []);
              renderTableBody("map_table_body", [], []);
              if (document.getElementById("map_stats")) {{
                document.getElementById("map_stats").innerHTML = "";
              }}
              if (mapLayer) mapLayer.clearLayers();
              if (mapTrack) {{
                mapTrack.remove();
                mapTrack = null;
              }}
              if (mapHeatLayer) {{
                mapHeatLayer.remove();
                mapHeatLayer = null;
              }}
              if (mapLegend) {{
                mapLegend.remove();
                mapLegend = null;
              }}
              return;
            }}

            const minLat = Math.min(...points.map((p) => p.lat));
            const maxLat = Math.max(...points.map((p) => p.lat));
            const minLon = Math.min(...points.map((p) => p.lon));
            const maxLon = Math.max(...points.map((p) => p.lon));
            const latSpan = Math.max(0.0001, maxLat - minLat);
            const lonSpan = Math.max(0.0001, maxLon - minLon);
            const padLat = Math.max(0.01, latSpan * 0.2);
            const padLon = Math.max(0.01, lonSpan * 0.2);
            const minLatPad = Math.max(-90, minLat - padLat);
            const maxLatPad = Math.min(90, maxLat + padLat);
            const minLonPad = Math.max(-180, minLon - padLon);
            const maxLonPad = Math.min(180, maxLon + padLon);
            const latSpanPad = Math.max(0.0001, maxLatPad - minLatPad);
            const lonSpanPad = Math.max(0.0001, maxLonPad - minLonPad);

            if (mapMessage) {{
              mapMessage.textContent = "Loading map...";
            }}
            try {{
              await loadLeaflet();
            }} catch (err) {{
              if (mapMessage) {{
                mapMessage.textContent = "Map tiles could not be loaded. Check your network connection.";
              }}
              return;
            }}
            if (!window.L) {{
              if (mapMessage) {{
                mapMessage.textContent = "Map library is unavailable.";
              }}
              return;
            }}
            if (mapMessage) {{
              mapMessage.textContent = "";
            }}

            if (!mapRef || !mapRef._container) {{
              if (mapRef) {{
                mapRef.remove();
              }}
              mapPanel.innerHTML = "";
              mapRef = L.map("map_panel", {{
                zoomSnap: 0.5,
                zoomControl: true
              }});
              if (!mapRef.getPane("markerPaneTop")) {{
                mapRef.createPane("markerPaneTop");
                mapRef.getPane("markerPaneTop").style.zIndex = 650;
              }}
              const streetTiles = L.tileLayer("https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png", {{
                maxZoom: 19,
                attribution: "&copy; OpenStreetMap contributors"
              }});
              const satelliteTiles = L.tileLayer(
                "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{{z}}/{{y}}/{{x}}",
                {{
                  maxZoom: 19,
                  attribution: "Tiles &copy; Esri"
                }}
              );
              mapTileLayer = (mapSatelliteEnabled ? satelliteTiles : streetTiles);
              mapTileLayer.on("tileerror", () => {{
                if (mapMessage) {{
                  mapMessage.textContent = "Map tiles could not be loaded. Check network access.";
                }}
              }});
              mapTileLayer.addTo(mapRef);
              mapLayer = L.layerGroup().addTo(mapRef);

              const controlRow = L.control({{ position: "bottomleft" }});
              controlRow.onAdd = () => {{
                const container = L.DomUtil.create("div", "map-button-row");
                const expandButton = L.DomUtil.create("button", "map-toggle-button", container);
                expandButton.type = "button";
                const setExpandState = () => {{
                  const isExpanded = mapPanel.classList.contains("map-expanded");
                  expandButton.innerHTML = isExpanded
                    ? '<span class="material-icons" aria-hidden="true">close_fullscreen</span>'
                    : '<span class="material-icons" aria-hidden="true">open_in_full</span>';
                  expandButton.title = isExpanded ? "Collapse map" : "Expand map";
                  expandButton.setAttribute("aria-label", expandButton.title);
                }};
                setExpandState();

                const markersButton = L.DomUtil.create("button", "map-toggle-button", container);
                markersButton.type = "button";
                markersButton.title = "Toggle markers";
                markersButton.setAttribute("aria-label", "Toggle markers");
                markersButton.innerHTML = '<span class="material-icons" aria-hidden="true">place</span>';
                markersButton.classList.toggle("is-active", mapMarkersEnabled);

                const satelliteButton = L.DomUtil.create("button", "map-toggle-button", container);
                satelliteButton.type = "button";
                satelliteButton.title = "Toggle satellite view";
                satelliteButton.setAttribute("aria-label", "Toggle satellite view");
                satelliteButton.innerHTML = '<span class="material-icons" aria-hidden="true">satellite_alt</span>';
                satelliteButton.classList.toggle("is-active", mapSatelliteEnabled);

                const heatButton = L.DomUtil.create("button", "map-toggle-button", container);
                heatButton.type = "button";
                heatButton.title = "Toggle heat map";
                heatButton.setAttribute("aria-label", "Toggle heat map");
                heatButton.innerHTML = '<span class="material-icons" aria-hidden="true">local_fire_department</span>';
                heatButton.classList.toggle("is-active", mapHeatEnabled);

                const trackButton = L.DomUtil.create("button", "map-toggle-button", container);
                trackButton.type = "button";
                trackButton.title = "Toggle track";
                trackButton.setAttribute("aria-label", "Toggle track");
                trackButton.innerHTML = '<span class="material-icons" aria-hidden="true">timeline</span>';
                if (mapTrackEnabled) trackButton.classList.add("is-active");

                L.DomEvent.disableClickPropagation(container);
                L.DomEvent.on(expandButton, "click", (event) => {{
                  L.DomEvent.stop(event);
                  mapPanel.classList.toggle("map-expanded");
                  setExpandState();
                  setTimeout(() => mapRef.invalidateSize(true), 60);
                }});
                L.DomEvent.on(heatButton, "click", (event) => {{
                  L.DomEvent.stop(event);
                  mapHeatEnabled = !mapHeatEnabled;
                  heatButton.classList.toggle("is-active", mapHeatEnabled);
                  generateMap();
                }});
                L.DomEvent.on(markersButton, "click", (event) => {{
                  L.DomEvent.stop(event);
                  mapMarkersEnabled = !mapMarkersEnabled;
                  markersButton.classList.toggle("is-active", mapMarkersEnabled);
                  generateMap();
                }});
                L.DomEvent.on(satelliteButton, "click", (event) => {{
                  L.DomEvent.stop(event);
                  mapSatelliteEnabled = !mapSatelliteEnabled;
                  satelliteButton.classList.toggle("is-active", mapSatelliteEnabled);
                  if (mapTileLayer) {{
                    mapRef.removeLayer(mapTileLayer);
                  }}
                  mapTileLayer = (mapSatelliteEnabled ? satelliteTiles : streetTiles);
                  mapTileLayer.addTo(mapRef);
                }});
                L.DomEvent.on(trackButton, "click", (event) => {{
                  L.DomEvent.stop(event);
                  mapTrackEnabled = !mapTrackEnabled;
                  trackButton.classList.toggle("is-active", mapTrackEnabled);
                  generateMap();
                }});
                return container;
              }};
              controlRow.addTo(mapRef);
            }}

            mapLayer.clearLayers();
            if (mapTrack) {{
              mapTrack.remove();
              mapTrack = null;
            }}
            if (mapHeatLayer) {{
              mapHeatLayer.remove();
              mapHeatLayer = null;
            }}
            if (mapLegend) {{
              mapLegend.remove();
              mapLegend = null;
            }}

            const latLngs = points.map((point) => [point.lat, point.lon]);
            const bounds = L.latLngBounds(latLngs);
            mapRef.fitBounds(bounds.pad(0.2));
            mapRef.invalidateSize(true);
            mapRef.whenReady(() => mapRef.invalidateSize(true));
            setTimeout(() => mapRef.invalidateSize(true), 150);

            if (mapHeatEnabled && window.L && typeof window.L.heatLayer === "function") {{
              if (mapMessage) mapMessage.textContent = "";
              const heatPoints = points.map((point) => [point.lat, point.lon, 0.6]);
              mapHeatLayer = window.L.heatLayer(heatPoints, {{
                radius: 22,
                blur: 18,
                maxZoom: 17
              }}).addTo(mapRef);
            }} else if (mapHeatEnabled && mapMessage) {{
              mapMessage.textContent = mapMarkersEnabled
                ? "Heat map unavailable; showing points instead."
                : "Heat map unavailable.";
            }}

            if (mapMarkersEnabled) {{
              points.forEach((point) => {{
                const marker = L.circleMarker([point.lat, point.lon], {{
                  radius: 4,
                  color: "#2563eb",
                  fillColor: "#60a5fa",
                  fillOpacity: 0.55,
                  weight: 1,
                  pane: "markerPaneTop"
                }});
                const label = point.timestamp
                  ? new Date(point.timestamp).toLocaleString()
                  : "Timestamp unavailable";
                marker.bindPopup(label);
                marker.addTo(mapLayer);
              }});
            }}
            if (track && points.length > 1) {{
              mapTrack = L.polyline(latLngs, {{ color: "#2563eb", weight: 2, opacity: 0.5 }}).addTo(mapRef);
            }}

            mapLegend = document.createElement("div");
            mapLegend.className = "map-legend";
            mapLegend.textContent = `${{points.length}} points`;
            mapPanel.appendChild(mapLegend);

            const statsBox = document.getElementById("map_stats");
            if (statsBox) {{
              statsBox.innerHTML = `
                <h3>Map summary</h3>
                <table class="stats-table">
                  <tr><td>Points</td><td>${{points.length}}</td></tr>
                  <tr><td>Latitude range</td><td>${{formatValue(latField, minLat)}} - ${{formatValue(latField, maxLat)}}</td></tr>
                  <tr><td>Longitude range</td><td>${{formatValue(lonField, minLon)}} - ${{formatValue(lonField, maxLon)}}</td></tr>
                </table>
              `;
            }}

            currentMapRows = points.map((point) => ({{
              "Timestamp": point.timestamp ? new Date(point.timestamp).toLocaleString() : "",
              "Latitude": formatValue(latField, point.lat),
              "Longitude": formatValue(lonField, point.lon)
            }}));
            renderTableHead("map_table_head", ["Timestamp", "Latitude", "Longitude"]);
            renderTableBody("map_table_body", ["Timestamp", "Latitude", "Longitude"], currentMapRows);
          }};

          const renderTableHead = (id, columns) => {{
            const head = document.getElementById(id);
            if (!head) return;
            head.innerHTML = columns.map((col) => `<th>${{col}}</th>`).join("");
          }};

          const renderTableBody = (id, columns, rows) => {{
            const body = document.getElementById(id);
            if (!body) return;
            body.innerHTML = rows.map((row) => {{
              const tds = columns.map((col) => `<td>${{row[col] ?? ""}}</td>`).join("");
              return `<tr>${{tds}}</tr>`;
            }}).join("");
          }};

            document.getElementById("generate_chart")?.addEventListener("click", generateAnalysis);
            document.getElementById("chart_type")?.addEventListener("change", () => {{
              updateOutlierUI();
              resetOutlierRanges();
            }});
            document.getElementById("field_select")?.addEventListener("change", resetOutlierRanges);
            document.getElementById("field_select_2")?.addEventListener("change", resetOutlierRanges);
            document.getElementById("field_select_y")?.addEventListener("change", () => {{
              updateOutlierUI();
              resetOutlierRanges();
            }});
            document.getElementById("port_filter")?.addEventListener("change", () => {{
              updateTimeBounds({{
                portValue: document.getElementById("port_filter")?.value.trim() || "",
                startId: "start_time",
                endId: "end_time",
                requireLocation: false
              }});
            }});
            document.getElementById("chart_expand")?.addEventListener("click", toggleChartExpand);
            document.getElementById("chart_reset_zoom")?.addEventListener("click", resetChartZoom);
            document.getElementById("chart_toggle_line")?.addEventListener("click", toggleChartLine);
            document.getElementById("chart_toggle_points")?.addEventListener("click", toggleChartPoints);
            document.getElementById("map_port_filter")?.addEventListener("change", () => {{
              updateTimeBounds({{
                portValue: document.getElementById("map_port_filter")?.value || "",
                startId: "map_start_time",
                endId: "map_end_time",
                requireLocation: true
              }});
            }});
            document.getElementById("ignore_zero_coords")?.addEventListener("change", () => {{
              updateMapPortOptions();
              updateTimeBounds({{
                portValue: document.getElementById("map_port_filter")?.value || "",
                startId: "map_start_time",
                endId: "map_end_time",
                requireLocation: true
              }});
            }});
            document.getElementById("generate_map")?.addEventListener("click", generateMap);

            updateOutlierUI();
            updateChartToggleButtons();
            renderDefaultMap();
            setAnalyticsPanelsVisible(false);
            if (!pickBestLat() || !pickBestLon()) {{
              const mapMessage = document.getElementById("map_message");
              if (mapMessage) {{
                mapMessage.textContent = "This decoded file does not include location fields to display a map.";
              }}
              const controls = document.querySelector(".map-controls");
              if (controls) controls.style.display = "none";
            }}
          }} catch (err) {{
            console.error("Analyze page error", err);
            const banner = document.getElementById("analysis_error");
            if (banner) {{
              banner.textContent = `Analyze error: ${{err && err.message ? err.message : err}}`;
              banner.style.display = "block";
            }}
          }}
        }})();
      </script>
    """

    active_page = "files" if saved_id else "decoders"
    return render_simple_page(
        title="Analyze",
        subtitle=f"Explore decoded payloads from {source_filename}.",
        body_html=body_html,
        active_page=active_page,
        page_title="Analyze results",
    )


@app.route("/generate-log", methods=["GET", "POST"])
@login_required
def generate_log_page():
    user_id = get_user_id()
    if request.method == "GET":
        log_id = request.args.get("log_id", "").strip()
        scan_token = request.args.get("scan_token", "").strip()
        generated_entry = get_stored_log_entry(log_id) if log_id else None
        return render_generator_page(
            generated_entry=generated_entry,
            generated_scan_token=scan_token,
        )

    allowed, retry_after = check_rate_limit("generate", user_id)
    if not allowed:
        form_values = get_generator_form_values(request.form)
        return render_generator_page(
            form_values=form_values,
            error_message=f"Rate limit exceeded. Try again in {retry_after} seconds.",
        )

    form_values = get_generator_form_values(request.form)
    try:
        log_buffer, filename = generate_logfile_bytes(form_values)
    except ValueError as exc:
        return render_generator_page(form_values=form_values, error_message=str(exc))

    size_hint = log_buffer.getbuffer().nbytes
    ok, message = check_user_log_quota(user_id, new_bytes=size_hint)
    if not ok:
        return render_generator_page(form_values=form_values, error_message=message)

    entry = store_generated_log(log_buffer, filename, user_id)
    ok, message = enforce_user_log_quota_after_store(user_id, entry)
    if not ok:
        return render_generator_page(form_values=form_values, error_message=message)
    audit_log(
        "log_generated",
        {"log_id": entry["id"], "filename": entry["filename"], "size": entry.get("size", 0)},
    )
    scan_token = ""
    scan_error = ""
    try:
        scan_token, _entry = scan_stored_log(entry["id"])
    except ValueError as exc:
        scan_error = str(exc)

    return render_generator_page(
        form_values=form_values,
        error_message=scan_error,
        generated_entry=entry,
        generated_scan_token=scan_token,
    )


def normalize_gateway_eui(gw_hex: str) -> bytes:
    """
    Takes a gateway EUI as hex string:
    - '0102030405060708'
    - or with ':' or '-' ('01:02:03:04:05:06:07:08')
    and returns 8 bytes.
    """
    gw_hex = gw_hex.replace(":", "").replace("-", "").strip()
    if len(gw_hex) != 16:
        raise ValueError(f"Gateway EUI must be 8 bytes (16 hex chars), got '{gw_hex}'")
    return bytes.fromhex(gw_hex)


def build_push_data(gateway_eui_hex: str, rxpk: dict) -> bytes:
    """
    Build a Semtech UDP PUSH_DATA packet:
    [0]    protocol version = 2
    [1-2]  random token
    [3]    identifier = 0x00 (PUSH_DATA)
    [4-11] gateway unique ID (8 bytes)
    JSON body: {"rxpk":[ rxpk ]}
    """
    # Header
    header = bytearray(12)
    header[0] = 0x02  # protocol version

    token = os.urandom(2)
    header[1] = token[0]
    header[2] = token[1]

    header[3] = 0x00  # PUSH_DATA

    gw_bytes = normalize_gateway_eui(gateway_eui_hex)
    header[4:12] = gw_bytes

    # Body
    body_obj = {"rxpk": [rxpk]}
    body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")

    return bytes(header) + body


if __name__ == "__main__":
    # Listen on all interfaces on port 18080
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "18080"))
    debug = env_flag("DEBUG", False)
    app.run(host=host, port=port, debug=debug)
