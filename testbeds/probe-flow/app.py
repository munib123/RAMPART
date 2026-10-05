"""probe-flow routes: request input enters here and reaches the sinks in other modules."""
import requests
from flask import Flask, abort, request

import auth
import client
import files
import settings
import settings_safe

app = Flask(__name__)


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = settings.CORS_ORIGIN
    return resp


@app.after_request
def add_cors_safe(resp):
    resp.headers["Access-Control-Allow-Origin"] = settings_safe.CORS_ORIGIN
    return resp


@app.after_request
def add_cors_public(resp):
    if request.path.startswith("/public/"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/login", methods=["POST"])
def login():
    auth.verify_login(request.form["username"], request.form["password"])
    return "welcome"


@app.route("/login-safe", methods=["POST"])
def login_safe():
    if not auth.verify_login(request.form["username"], request.form["password"]):
        abort(401)
    return "welcome"


@app.route("/webhook", methods=["POST"])
def webhook():
    return {"status": client.notify(request.form["callback_url"], {}).status_code}


@app.route("/webhook-safe", methods=["POST"])
def webhook_safe():
    return {"status": client.notify_safe(request.form["callback_url"], {}).status_code}


@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    return requests.get(target, timeout=5).text


@app.route("/export")
def export():
    return files.read_export(request.args.get("name", ""))


@app.route("/export-safe")
def export_safe():
    return files.read_export_safe(request.args.get("name", ""))


def run_safe():
    app.run(debug=settings_safe.DEBUG)


if __name__ == "__main__":
    app.run(debug=settings.DEBUG)
