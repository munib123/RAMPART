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
    allowed_sorts = {"id", "name", "price", "id asc", "name asc", "price asc", "id desc", "name desc", "price desc"}
    if sort.lower() not in allowed_sorts:
        raise ValueError("Invalid sort parameter")
    query = "SELECT * FROM products WHERE name LIKE ? ORDER BY " + sort
    return conn.execute(query, ('%' + term + '%',)).fetchall()


def user_by_name(username):
    """Fetch a user row by username (parameterised)."""
    conn = get_db()
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
