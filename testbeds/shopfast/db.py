"""ShopFast — thin database access layer (SQLite)."""
import sqlite3

import config


def get_db():
    conn = sqlite3.connect(config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def find_product(product_id):
    """Look up a single product by id."""
    conn = get_db()
    query = f"SELECT * FROM products WHERE id = {product_id}"
    return conn.execute(query).fetchone()


def search_products(term, sort):
    """Full-text-ish search with a caller-chosen sort column."""
    conn = get_db()
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%' ORDER BY " + sort
    return conn.execute(query).fetchall()


def user_by_name(username):
    """Fetch a user row by username (parameterised)."""
    conn = get_db()
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
