"""Fix 6 probe: `x in [...]` on something unrelated is not a field allow-list."""
import db

ALLOWED_FIELDS = ("display_name", "timezone")


def update_settings(user_id, section, data):
    conn = db.get_db()
    if section in ["profile", "prefs"]:            # unrelated membership test; must NOT count as a guard
        conn.execute("UPDATE audit SET last_section = ? WHERE id = ?", (section, user_id))
    fields = ", ".join(f"{k} = '{v}'" for k, v in data.items())
    conn.execute(f"UPDATE users SET {fields} WHERE id = {user_id}")
    conn.commit()


def update_settings_safe(user_id, data):
    conn = db.get_db()
    clean = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}
    fields = ", ".join(f"{k} = '{v}'" for k, v in clean.items())
    conn.execute(f"UPDATE users SET {fields} WHERE id = {user_id}")
    conn.commit()
