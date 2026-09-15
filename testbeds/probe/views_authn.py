"""Fix 2 probe: authentication is not authorization."""
from flask import abort
from flask_login import login_required
import db


@login_required
def order_detail(order_id):
    """Any logged-in user can read any order: authenticated, not authorized."""
    conn = db.get_db()
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
