"""probe-flow file access: a caller-supplied name joined onto a base directory."""
import os

from werkzeug.utils import secure_filename

EXPORT_DIR = "/srv/exports"


def read_export(name):
    path = os.path.join(EXPORT_DIR, name)
    with open(path, "rb") as fh:
        return fh.read()


def read_export_safe(name):
    path = os.path.join(EXPORT_DIR, secure_filename(name))
    with open(path, "rb") as fh:
        return fh.read()
