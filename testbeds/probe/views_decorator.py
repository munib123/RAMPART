"""Fix 7 probe: a decorator on get_note_extra must not protect get_note.

pysrc2cpg lowers the decorator to a module-scope call `get_note_extra = check_owner(get_note_extra)`.
The old test `c.contains(name)` asks whether that code contains "get_note" - it does, as a
substring of the longer name - so the undecorated get_note was credited with a guard."""
from auth import check_owner
import db


def get_note(note_id):
    conn = db.get_db()
    return conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()


@check_owner
def get_note_extra(note_id):
    conn = db.get_db()
    return conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
