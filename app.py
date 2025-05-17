# Cheat Resale License Platform - app.py

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3, uuid, os, hashlib

app = Flask(__name__)
app.secret_key = "super_secure_key"
DB_PATH = "resale.db"

# -------------------- DATABASE INIT --------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS license_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE,
        status TEXT,
        hwid TEXT,
        ip TEXT,
        expires_at TIMESTAMP,
        cheat_type TEXT,
        created_by TEXT,
        revoked_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT,
        hwid TEXT,
        ip TEXT,
        event TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid TEXT UNIQUE,
        reason TEXT,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    conn.commit()
    conn.close()

# -------------------- HELPERS --------------------
def get_user_role(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username = ?", (username,))
    role = c.fetchone()
    conn.close()
    return role[0] if role else None

def log_event(key, hwid, ip, event):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO logs (key, hwid, ip, event) VALUES (?, ?, ?, ?)", (key, hwid, ip, event))
    conn.commit()
    conn.close()

# -------------------- AUTH --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user, pw = request.form["username"], request.form["password"]
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (user,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[0], pw):
            session["username"] = user
            session["role"] = get_user_role(user)
            return redirect("/dashboard")
        flash("Invalid login.", "danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return redirect("/admin" if session['role'] == 'admin' else "/tech")

@app.route("/admin")
def admin():
    if session.get("role") != "admin": return redirect("/login")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM license_keys ORDER BY created_at DESC")
    keys = c.fetchall()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return render_template("admin_dashboard.html", keys=keys, logs=logs)

@app.route("/tech")
def tech():
    if session.get("role") != "tech": return redirect("/login")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM license_keys ORDER BY created_at DESC")
    keys = c.fetchall()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return render_template("tech_dashboard.html", keys=keys, logs=logs)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -------------------- PUBLIC --------------------
@app.route("/")
def home(): return render_template("index.html")

@app.route("/cheats")
def cheats(): return render_template("cheats.html")

@app.route("/cheats/rust")
def cheat_rust(): return render_template("cheat_rust.html")

@app.route("/purchase/rust")
def purchase_rust(): return render_template("purchase_rust.html")

@app.route("/success")
def success():
    key = request.args.get("key")
    return render_template("success.html", key=key)

@app.route("/faq")
def faq(): return render_template("faq.html")

# -------------------- LICENSE ADMIN --------------------
@app.route("/generate", methods=["POST"])
def generate():
    if session.get("role") != "admin": return "Unauthorized", 403
    key = str(uuid.uuid4()).upper()
    expires = datetime.now() + timedelta(days=30)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO license_keys (key, status, expires_at, cheat_type, created_by) VALUES (?, ?, ?, ?, ?)",
              (key, "unused", expires, "rust", session["username"]))
    conn.commit()
    conn.close()
    flash("Key generated: " + key, "success")
    return redirect("/admin")

@app.route("/revoke", methods=["POST"])
def revoke():
    if session.get("role") != "admin": return "Unauthorized", 403
    key = request.form["key"]
    reason = request.form["reason"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE license_keys SET status = 'revoked', revoked_reason = ? WHERE key = ?", (reason, key))
    conn.commit()
    conn.close()
    flash("Key revoked.", "warning")
    return redirect("/admin")

# -------------------- API ENDPOINTS --------------------
@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json()
    key = data.get("key")
    hwid = data.get("hwid")
    ip = request.remote_addr

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Check blacklist
    c.execute("SELECT * FROM blacklist WHERE hwid = ?", (hwid,))
    if c.fetchone():
        log_event(key, hwid, ip, "blacklisted")
        return jsonify({"status": "banned"})

    # Check key
    c.execute("SELECT status, hwid, expires_at FROM license_keys WHERE key = ?", (key,))
    row = c.fetchone()

    if not row:
        log_event(key, hwid, ip, "invalid_key")
        return jsonify({"status": "invalid"})

    status, bound_hwid, expires = row
    now = datetime.now()

    if datetime.strptime(expires, "%Y-%m-%d %H:%M:%S") < now:
        log_event(key, hwid, ip, "expired")
        return jsonify({"status": "expired"})

    if status == "revoked":
        log_event(key, hwid, ip, "revoked_attempt")
        return jsonify({"status": "revoked"})

    if bound_hwid and bound_hwid != hwid:
        log_event(key, hwid, ip, "hwid_mismatch")
        return jsonify({"status": "hwid_mismatch"})

    if not bound_hwid:
        c.execute("UPDATE license_keys SET hwid = ?, status = 'active', ip = ? WHERE key = ?", (hwid, ip, key))
        log_event(key, hwid, ip, "bound_new_hwid")
    else:
        log_event(key, hwid, ip, "verified")

    conn.commit()
    conn.close()
    return jsonify({"status": "valid"})

@app.route("/api/download")
def api_download():
    key = request.args.get("key")
    hwid = request.args.get("hwid")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT status, hwid FROM license_keys WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    if row and row[0] == "active" and row[1] == hwid:
        return send_file("loader_stub.exe", as_attachment=True)
    return "Unauthorized", 403

@app.route("/api/log", methods=["POST"])
def api_log():
    data = request.get_json()
    log_event(data.get("key"), data.get("hwid"), request.remote_addr, data.get("event"))
    return jsonify({"ok": True})

# -------------------- MAIN --------------------
if __name__ == "__main__":
    init_db()
    if not os.path.exists("loader_stub.exe"):
        with open("loader_stub.exe", "wb") as f: f.write(b"stub")
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = 'admin'")
        if not c.fetchone():
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      ("admin", generate_password_hash("admin123"), "admin"))
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      ("tech", generate_password_hash("tech123"), "tech"))
        conn.commit()
        conn.close()
    except:
        pass
        app.run(debug=False, host='0.0.0.0', port=10000)

