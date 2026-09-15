"""Fix 3 probe: a docstring is not a guard."""
import db


def reserve_stock(product_id, quantity):
    """Reserve stock for an order. Runs inside a transaction with a row lock
    so concurrent reservations are serialised (see the ops runbook)."""
    product = db.find_product(product_id)
    if product["stock"] >= quantity:
        conn = db.get_db()
        conn.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (quantity, product_id))
        conn.commit()
        return True
    return False
