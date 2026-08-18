# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5788_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5788_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 214-241 of the vulnerable file.

        return [etag_str]
    etags = [e.encode('ascii').decode('unicode_escape') for e in etags]
    return etags

def quote_etag(etag):
    """
    Wraps a string in double quotes escaping contents as necessary.
    """
    return '"%s"' % etag.replace('\\', '\\\\').replace('"', '\\"')

def same_origin(url1, url2):
    """
    Checks if two URLs are 'same-origin'
    """
    p1, p2 = urllib_parse.urlparse(url1), urllib_parse.urlparse(url2)
    return (p1.scheme, p1.hostname, p1.port) == (p2.scheme, p2.hostname, p2.port)

def is_safe_url(url, host=None):
    """
    Return ``True`` if the url is a safe redirection (i.e. it doesn't point to
    a different host).

    Always returns ``False`` on an empty url.
    """
    if not url:
        return False
    netloc = urllib_parse.urlparse(url)[1]
    return not netloc or netloc == host
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -231,11 +231,12 @@
 def is_safe_url(url, host=None):
     """
     Return ``True`` if the url is a safe redirection (i.e. it doesn't point to
-    a different host).
+    a different host and uses a safe scheme).
 
     Always returns ``False`` on an empty url.
     """
     if not url:
         return False
-    netloc = urllib_parse.urlparse(url)[1]
-    return not netloc or netloc == host
+    url_info = urllib_parse.urlparse(url)
+    return (not url_info.netloc or url_info.netloc == host) and \
+        (not url_info.scheme or url_info.scheme in ['http', 'https'])
```
