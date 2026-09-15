"""Fix 5 probe: abort(404) is not-found, not authorization."""
from flask import abort
import db


def invoice_detail(invoice_id):
    conn = db.get_db()
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if row is None:
        abort(404)
    return row
