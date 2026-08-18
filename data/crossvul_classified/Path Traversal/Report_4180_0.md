# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 4180_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4180_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 12-52 of the vulnerable file.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
import contextlib
import errno
import fnmatch
import json
import hashlib
import hmac
import pathlib
import typing

import flask

app = flask.Flask("xmpp-http-upload")
app.config.from_envvar("XMPP_HTTP_UPLOAD_CONFIG")
application = app

if app.config['ENABLE_CORS']:
    from flask_cors import CORS
    CORS(app)


def sanitized_join(path: str, root: pathlib.Path) -> pathlib.Path:
    result = (root / path).absolute()
    if not str(result).startswith(str(root) + "/"):
        raise ValueError("resulting path is outside root")
    return result


def get_paths(base_path: pathlib.Path):
    data_file = pathlib.Path(str(base_path) + ".data")
    metadata_file = pathlib.Path(str(base_path) + ".meta")

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 import typing
 
 import flask
+import werkzeug.exceptions
 
 app = flask.Flask("xmpp-http-upload")
 app.config.from_envvar("XMPP_HTTP_UPLOAD_CONFIG")
@@ -39,16 +40,11 @@
     CORS(app)
 
 
-def sanitized_join(path: str, root: pathlib.Path) -> pathlib.Path:
-    result = (root / path).absolute()
-    if not str(result).startswith(str(root) + "/"):
-        raise ValueError("resulting path is outside root")
-    return result
-
-
-def get_paths(base_path: pathlib.Path):
-    data_file = pathlib.Path(str(base_path) + ".data")
-    metadata_file = pathlib.Path(str(base_path) + ".meta")
+def get_paths(root: str, sub_path: str) \
+        -> typing.Tuple[pathlib.Path, pathlib.Path]:
+    base_path = flask.safe_join(root, sub_path)
+    data_file = pathlib.Path(base_path + ".data")
+    metadata_file = pathlib.Path(base_path + ".meta")
 
     return data_file, metadata_file
 
@@ -58,15 +54,10 @@
         return json.load(f)
 
 
-def get_info(path: str, root: pathlib.Path) -> typing.Tuple[
+def get_info(path: str) -> typing.Tuple[
         pathlib.Path,
         dict]:
-    dest_path = sanitized_join(
-        path,
-        pathlib.Path(app.config["DATA_ROOT"]),
-    )
-
-    data_file, metadata_file = get_paths(dest_path)
+    data_file, metadata_file = get_paths(app.config["DATA_ROOT"], path)
 
     return data_file, load_metadata(metadata_file)
 
@@ -104,11 +95,8 @@
 @app.route("/<path:path>", methods=["PUT"])
 def put_file(path):
     try:
-        dest_path = sanitized_join(
-            path,
-            pathlib.Path(app.config["DATA_ROOT"]),
-        )
-    except ValueError:
+        data_file, metadata_file = get_paths(app.config["DATA_ROOT"], path)
+    except werkzeug.exceptions.NotFound:
         return flask.Response(
             "Not Found",
             404,
@@ -134,8 +122,7 @@
         "application/octet-stream",
     )
 
-    dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
-    data_file, metadata_file = get_paths(dest_path)
+    data_file.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
 
     try:
         with write_file(data_file) as fout:
@@ -189,13 +176,10 @@
 @app.route("/<path:path>", methods=["HEAD"])
 def head_file(path):
     try:
-        data_file, metadata = get_info(
-            path,
-            pathlib.Path(app.config["DATA_ROOT"])
-        )
+        data_file, metadata = get_info(path)
 
         stat = data_file.stat()
-    except (OSError, ValueError):
+    except (OSError, werkzeug.exceptions.NotFound):
         return flask.Response(
             "Not Found",
             404,
@@ -214,11 +198,8 @@
 @app.route("/<path:path>", methods=["GET"])
 def get_file(path):
     try:
-        data_file, metadata = get_info(
-            path,
-            pathlib.Path(app.config["DATA_ROOT"])
-        )
-    except (OSError, ValueError):
+        data_file, metadata = get_info(path)
+    except (OSError, werkzeug.exceptions.NotFound):
         return flask.Response(
             "Not Found",
             404,
```
