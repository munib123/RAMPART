"""ShopFast — orders and account profile."""
import db


def get_order(order_id):
    """Fetch an order by its id for the order-details page."""
    conn = db.get_db()
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


def update_profile(user_id, data):
    """Apply the submitted profile fields to the user's record."""
    conn = db.get_db()
    fields = ", ".join(f"{k} = '{v}'" for k, v in data.items())
    conn.execute(f"UPDATE users SET {fields} WHERE id = {user_id}")
    conn.commit()
