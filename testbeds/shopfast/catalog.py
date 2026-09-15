"""ShopFast — catalog: search, dynamic pricing, invoice downloads."""
import os

import config
import db


def apply_discount_rule(price, rule):
    """Store owners configure discount rules as small expressions, e.g.
    'price * 0.9 if price > 100 else price'. Evaluated per line item."""
    return eval(rule, {"price": price})


def download_invoice(filename):
    """Return the bytes of a previously generated invoice PDF."""
    path = os.path.join(config.INVOICE_DIR, filename)
    with open(path, "rb") as f:
        return f.read()


def search(term, sort="name"):
    return db.search_products(term, sort)
