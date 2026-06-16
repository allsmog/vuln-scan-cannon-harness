from flask import Flask, request
from db import run_query
import yaml

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # The /search SQL injection was "fixed" in a past commit (see git log).
    # In a real incomplete fix, the patch parameterizes here but misses siblings.
    return run_query("SELECT * FROM items WHERE name = '" + term + "'")


@app.route("/profile")
def profile():
    uid = request.args.get("uid", "")
    # Sibling of the search sink — the variant a /search-only fix would miss.
    return run_query("SELECT * FROM users WHERE id = '" + uid + "'")


@app.route("/config", methods=["POST"])
def load_config():
    # PyYAML footgun: yaml.load (not safe_load) on request data is RCE.
    data = yaml.load(request.data)
    return {"ok": True, "keys": list(data or {})}
