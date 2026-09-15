"""ShopFast — a small e-commerce backend (Flask). Demo/test target."""
import os

from flask import Flask, request, redirect, render_template_string

import config
import auth
import db
import catalog
import payments
import orders

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = config.CORS_ALLOW_ORIGIN
    return resp


@app.route("/products/<product_id>")
def product(product_id):
    return dict(db.find_product(product_id) or {})


@app.route("/search")
def search():
    term = request.args.get("q", "")
    sort = request.args.get("sort", "name")
    return {"results": [dict(r) for r in catalog.search(term, sort)]}


@app.route("/login", methods=["POST"])
def login():
    auth.verify_login(request.form["username"], request.form["password"])
    return redirect(request.args.get("next", "/"))


@app.route("/hello")
def hello():
    name = request.args.get("name", "shopper")
    return render_template_string("<h1>Welcome " + name + "</h1>")


@app.route("/invoice")
def invoice():
    return catalog.download_invoice(request.args.get("file", ""))


@app.route("/thumbnail")
def thumbnail():
    img = request.args.get("img", "")
    os.system("convert " + os.path.join(config.UPLOAD_DIR, img) + " -resize 100x100 thumbs/" + img)
    return "ok"


@app.route("/order/<order_id>")
def order(order_id):
    return dict(orders.get_order(order_id) or {})


@app.route("/profile", methods=["POST"])
def profile():
    orders.update_profile(request.form["user_id"], request.form.to_dict())
    return "updated"


@app.route("/webhook", methods=["POST"])
def webhook():
    resp = payments.notify_webhook(request.form["callback_url"], {})
    return {"status": resp.status_code}


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
