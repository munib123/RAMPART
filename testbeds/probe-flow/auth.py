"""probe-flow authentication: credential checks whose result is (not) used."""
import os

from werkzeug.security import check_password_hash

import db
import settings


def verify_login(username, password):
    row = db.user_by_name(username)
    if not row:
        return None
    if check_password_hash(row["password_hash"], password):
        return db.issue_session(row)
    return None


def change_email(username, password, new_email):
    row = db.user_by_name(username)
    check_password_hash(row["password_hash"], password)
    db.set_email(row["id"], new_email)


def change_email_safe(username, password, new_email):
    row = db.user_by_name(username)
    if not check_password_hash(row["password_hash"], password):
        raise PermissionError("bad password")
    db.set_email(row["id"], new_email)


def is_support_login(username, password):
    return username == "support" and password == settings.SUPPORT_PASSWORD


def is_support_login_safe(username, password):
    expected = os.environ.get("SUPPORT_PASSWORD")
    return bool(expected) and username == "support" and password == expected
