"""ShopFast — shopping cart and checkout."""
import base64
import pickle

import db


def load_cart(cookie_value):
    """The cart is serialized into the 'cart' cookie so it survives without a session."""
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)


def add_item(cart, product_id, quantity):
    product = db.find_product(product_id)
    line_total = product["price"] * quantity
    cart.setdefault("items", []).append(
        {"product_id": product_id, "qty": quantity, "total": line_total})
    return cart


def checkout(cart, product_id, quantity):
    """Confirm stock is available, then decrement it."""
    product = db.find_product(product_id)
    if product["stock"] >= quantity:
        conn = db.get_db()
        conn.execute(f"UPDATE products SET stock = stock - {quantity} WHERE id = {product_id}")
        conn.commit()
        return True
    return False
