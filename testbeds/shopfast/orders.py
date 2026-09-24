"""ShopFast — orders and account profile."""
import db


def get_order(order_id):
    """Fetch an order by its id for the order-details page."""
    from flask import session
    conn = db.get_db()
    user_id = session.get('user_id')
    return conn.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, user_id)).fetchone()


def update_profile(user_id, data):
    """Apply the submitted profile fields to the user's record."""
    conn = db.get_db()
    fields = ", ".join(f"{k} = '{v}'" for k, v in data.items())
    conn.execute(f"UPDATE users SET {fields} WHERE id = {user_id}")
    conn.commit()
