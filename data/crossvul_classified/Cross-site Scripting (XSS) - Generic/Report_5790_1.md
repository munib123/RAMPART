# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in python
**Pair ID:** 5790_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5790_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```python
Lines 211-238 of the vulnerable file.

    def same_origin(url1, url2):
        """
        Checks if two URLs are 'same-origin'
        """
        p1, p2 = urlparse.urlparse(url1), urlparse.urlparse(url2)
        return (p1.scheme, p1.hostname, p1.port) == (p2.scheme, p2.hostname, p2.port)
else:
    # Python 2.5 compatibility. This actually works for Python 2.6 and above,
    # but the above definition is much more obviously correct and so is
    # preferred going forward.
    def same_origin(url1, url2):
        """
        Checks if two URLs are 'same-origin'
        """
        p1, p2 = urlparse.urlparse(url1), urlparse.urlparse(url2)
        return p1[0:2] == p2[0:2]

def is_safe_url(url, host=None):
    """
    Return ``True`` if the url is a safe redirection (i.e. it doesn't point to
    a different host).

    Always returns ``False`` on an empty url.
    """
    if not url:
        return False
    netloc = urlparse.urlparse(url)[1]
    return not netloc or netloc == host
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -228,11 +228,12 @@
 def is_safe_url(url, host=None):
     """
     Return ``True`` if the url is a safe redirection (i.e. it doesn't point to
-    a different host).
+    a different host and uses a safe scheme).
 
     Always returns ``False`` on an empty url.
     """
     if not url:
         return False
-    netloc = urlparse.urlparse(url)[1]
-    return not netloc or netloc == host
+    url_info = urlparse.urlparse(url)
+    return (not url_info[1] or url_info[1] == host) and \
+        (not url_info[0] or url_info[0] in ['http', 'https'])
```
