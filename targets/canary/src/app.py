"""Deliberately vulnerable demo app — for cannon's smoke test only.

DO NOT deploy. Every "bug" here is planted on purpose.
"""
import os
import sqlite3
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

# BUG (planted): hardcoded secret committed in source. CWE-798.
SECRET_KEY = "demo_flask_secret_key_not_real_0000"
app.config["SECRET_KEY"] = SECRET_KEY

DB = "/var/data/app.db"
DATA_DIR = "/var/data/files"


def db():
    return sqlite3.connect(DB)


@app.route("/users")
def get_user():
    # BUG (planted): SQL injection — name is interpolated straight into SQL. CWE-89.
    name = request.args.get("name", "")
    conn = db()
    query = "SELECT id, email FROM users WHERE name = '%s'" % name
    row = conn.execute(query).fetchone()
    return {"user": row}


@app.route("/lookup")
def lookup_user():
    # NOT A BUG (bait): looks like the handler above but is parameterized.
    # A good verifier should reject this as a false positive.
    uid = request.args.get("id", "")
    conn = db()
    row = conn.execute("SELECT id, email FROM users WHERE id = ?", (uid,)).fetchone()
    return {"user": row}


@app.route("/ping")
def ping():
    # BUG (planted): command injection — host flows into a shell. CWE-78.
    # (The design doc calls this endpoint "safe" — it is not. Verify the code.)
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return {"output": out.decode(errors="replace")}


@app.route("/download")
def download():
    # BUG (planted): path traversal — filename is joined without containment. CWE-22.
    filename = request.args.get("file", "")
    path = os.path.join(DATA_DIR, filename)
    return send_file(path)


@app.route("/admin/delete")
def admin_delete():
    # BUG (planted): missing access control — no auth check on a destructive
    # admin action; anyone can call it. CWE-862.
    user_id = request.args.get("id", "")
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
