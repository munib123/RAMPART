# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 1890_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1890_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 44-84 of the vulnerable file.

try:
    from hashlib import sha1 as _sha, md5 as _md5
except ImportError:
    # prior to Python 2.5, these were separate modules
    import sha
    import md5

    _sha = sha.new
    _md5 = md5.new
import hmac
from gettext import gettext as _
import socket

try:
    from httplib2 import socks
except ImportError:
    try:
        import socks
    except (ImportError, AttributeError):
        socks = None

# Build the appropriate socket wrapper for ssl
ssl = None
ssl_SSLError = None
ssl_CertificateError = None
try:
    import ssl  # python 2.6
except ImportError:
    pass
if ssl is not None:
    ssl_SSLError = getattr(ssl, "SSLError", None)
    ssl_CertificateError = getattr(ssl, "CertificateError", None)


def _ssl_wrap_socket(
    sock, key_file, cert_file, disable_validation, ca_certs, ssl_version, hostname, key_password
):
    if disable_validation:
        cert_reqs = ssl.CERT_NONE
    else:
        cert_reqs = ssl.CERT_REQUIRED
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,6 +61,8 @@
         import socks
     except (ImportError, AttributeError):
         socks = None
+from httplib2 import auth
+from httplib2.error import *
 
 # Build the appropriate socket wrapper for ssl
 ssl = None
@@ -75,9 +77,7 @@
     ssl_CertificateError = getattr(ssl, "CertificateError", None)
 
 
-def _ssl_wrap_socket(
-    sock, key_file, cert_file, disable_validation, ca_certs, ssl_version, hostname, key_password
-):
+def _ssl_wrap_socket(sock, key_file, cert_file, disable_validation, ca_certs, ssl_version, hostname, key_password):
     if disable_validation:
         cert_reqs = ssl.CERT_NONE
     else:
@@ -101,12 +101,7 @@
         if key_password:
             raise NotSupportedOnThisPlatform("Certificate with password is not supported.")
         return ssl.wrap_socket(
-            sock,
-            keyfile=key_file,
-            certfile=cert_file,
-            cert_reqs=cert_reqs,
-            ca_certs=ca_certs,
-            ssl_version=ssl_version,
+            sock, keyfile=key_file, certfile=cert_file, cert_reqs=cert_reqs, ca_certs=ca_certs, ssl_version=ssl_version,
         )
 
 
@@ -277,6 +272,7 @@
 DEFAULT_MAX_REDIRECTS = 5
 
 from httplib2 import certs
+
 CA_CERTS = certs.where()
 
 # Which headers are hop-by-hop headers by default
@@ -365,12 +361,7 @@
 
 
 def _normalize_headers(headers):
-    return dict(
-        [
-            (key.lower(), NORMALIZE_SPACE.sub(value, " ").strip())
-            for (key, value) in headers.iteritems()
-        ]
-    )
+    return dict([(key.lower(), NORMALIZE_SPACE.sub(value, " ").strip()) for (key, value) in headers.iteritems()])
 
 
 def _parse_cache_control(headers):
@@ -378,13 +369,9 @@
     if "cache-control" in headers:
         parts = headers["cache-control"].split(",")
         parts_with_args = [
-            tuple([x.strip().lower() for x in part.split("=", 1)])
-            for part in parts
-            if -1 != part.find("=")
+            tuple([x.strip().lower() for x in part.split("=", 1)]) for part in parts if -1 != part.find("=")
         ]
-        parts_wo_args = [
-            (name.strip().lower(), 1) for name in parts if -1 == name.find("=")
-        ]
+        parts_wo_args = [(name.strip().lower(), 1) for name in parts if -1 == name.find("=")]
         retval = dict(parts_with_args + parts_wo_args)
     return retval
 
@@ -394,55 +381,6 @@
 # so disabled by default, falling back to relaxed parsing.
 # Set to true to turn on, usefull for testing servers.
 USE_WWW_AUTH_STRICT_PARSING = 0
-
-# In regex below:
-#    [^\0-\x1f\x7f-\xff()<>@,;:\\\"/[\]?={} \t]+             matches a "token" as defined by HTTP
-#    "(?:[^\0-\x08\x0A-\x1f\x7f-\xff\\\"]|\\[\0-\x7f])*?"    matches a "quoted-string" as defined by HTTP, when LWS have already been replaced by a single space
-# Actually, as an auth-param value can be either a token or a quoted-string, they are combined in a single pattern which matches both:
-#    \"?((?<=\")(?:[^\0-\x1f\x7f-\xff\\\"]|\\[\0-\x7f])*?(?=\")|(?<!\")[^\0-\x08\x0A-\x1f\x7f-\xff()<>@,;:\\\"/[\]?={} \t]+(?!\"))\"?
-WWW_AUTH_STRICT = re.compile(
-    r"^(?:\s*(?:,\s*)?([^\0-\x1f\x7f-\xff()<>@,;:\\\"/[\]?={} \t]+)\s*=\s*\"?((?<=\")(?:[^\0-\x08\x0A-\x1f\x7f-\xff\\\"]|\\[\0-\x7f])*?(?=\")|(?<!\")[^\0-\x1f\x7f-\xff()<>@,;:\\\"/[\]?={} \t]+(?!\"))\"?)(.*)$"
-)
-WWW_AUTH_RELAXED = re.compile(
-    r"^(?:\s*(?:,\s*)?([^ \t\r\n=]+)\s*=\s*\"?((?<=\")(?:[^\\\"]|\\.)*?(?=\")|(?<!\")[^ \t\r\n,]+(?!\"))\"?)(.*)$"
-)
-UNQUOTE_PAIRS = re.compile(r"\\(.)")
-
-
-def _parse_www_authenticate(headers, headername="www-authenticate"):
-    """Returns a dictionary of dictionaries, one dict
-    per auth_scheme."""
-    retval = {}
-    if headername in headers:
-        try:
-
-            authenticate = headers[headername].strip()
-            www_auth = (
-                USE_WWW_AUTH_STRICT_PARSING and WWW_AUTH_STRICT or WWW_AUTH_RELAXED
-            )
-            while authenticate:
-                # Break off the scheme at the beginning of the line
-                if headername == "authentication-info":
-                    (auth_scheme, the_rest) = ("digest", authenticate)
-                else:
-                    (auth_scheme, the_rest) = authenticate.split(" ", 1)
-                # Now loop over all the key value pairs that come after the scheme,
-                # being careful not to roll into the next scheme
-                match = www_auth.search(the_rest)
-                auth_params = {}
-                while match:
-                    if match and len(match.groups()) == 3:
-                        (key, value, the_rest) = match.groups()
-                        auth_params[key.lower()] = UNQUOTE_PAIRS.sub(
-                            r"\1", value
-                        )  # '\\'.join([x.replace('\\', '') for x in value.split('\\\\')])
-                    match = www_auth.search(the_rest)
-                retval[auth_scheme.lower()] = auth_params
-                authenticate = the_rest.strip()
-
-        except ValueError:
-            raise MalformedHeader("WWW-Authenticate")
-    return retval
 
 
 # TODO: add current time as _entry_disposition argument to avoid sleep in tests
@@ -478,10 +416,7 @@
     cc = _parse_cache_control(request_headers)
     cc_response = _parse_cache_control(response_headers)
 
-    if (
-        "pragma" in request_headers
-        and request_headers["pragma"].lower().find("no-cache") != -1
-    ):
+    if "pragma" in request_headers and request_headers["pragma"].lower().find("no-cache") != -1:
         retval = "TRANSPARENT"
         if "cache-control" not in request_headers:
             request_headers["cache-control"] = "no-cache"
@@ -540,8 +475,7 @@
     except (IOError, zlib.error):
         content = ""
         raise FailedToDecompressContent(
-            _("Content purported to be compressed with %s but failed to decompress.")
-            % response.get("content-encoding"),
+            _("Content purported to be compressed with %s but failed to decompress.") % response.get("content-encoding"),
             response,
             content,
         )
@@ -587,17 +521,12 @@
 
 
 def _cnonce():
-    dig = _md5(
-        "%s:%s"
-        % (time.ctime(), ["0123456789"[random.randrange(0, 9)] for i in range(20)])
-    ).hexdigest()
+    dig = _md5("%s:%s" % (time.ctime(), ["0123456789"[random.randrange(0, 9)] for i in range(20)])).hexdigest()
     return dig[:16]
 
 
 def _wsse_username_token(cnonce, iso_now, password):
-    return base64.b64encode(
-        _sha("%s%s%s" % (cnonce, iso_now, password)).digest()
-    ).strip()
+    return base64.b64encode(_sha("%s%s%s" % (cnonce, iso_now, password)).digest()).strip()
 
 
 # For credentials we need two things, first
@@ -610,9 +539,7 @@
 
 
 class Authentication(object):
-    def __init__(
-        self, credentials, host, request_uri, headers, response, content, http
-    ):
+    def __init__(self, credentials, host, request_uri, headers, response, content, http):
         (scheme, authority, path, query, fragment) = parse_uri(request_uri)
         self.path = path
         self.host = host
@@ -645,55 +572,32 @@
 
 
 class BasicAuthentication(Authentication):
-    def __init__(
-        self, credentials, host, request_uri, headers, response, content, http
-    ):
-        Authentication.__init__(
-            self, credentials, host, request_uri, headers, response, content, http
-        )
+    def __init__(self, credentials, host, request_uri, headers, response, content, http):
+        Authentication.__init__(self, credentials, host, request_uri, headers, response, content, http)
 
     def request(self, method, request_uri, headers, content):
         """Modify the request headers to add the appropriate
         Authorization header."""
-        headers["authorization"] = (
-            "Basic " + base64.b64encode("%s:%s" % self.credentials).strip()
-        )
... (diff truncated)
```
