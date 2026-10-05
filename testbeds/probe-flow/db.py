"""probe-flow data access stubs (the rules never need their bodies)."""


def user_by_name(username):
    return {"id": 1, "password_hash": "", "username": username}


def issue_session(row):
    return {"sub": row["id"]}


def set_email(user_id, email):
    return None
