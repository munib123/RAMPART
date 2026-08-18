# CrossVul Fix Pair: Credentials Management Errors in python
**Pair ID:** 743_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `743_1`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```python
Lines 154-197 of the vulnerable file.

        if i < 0:
            return url, ''
    else:
        i = url.find(';')
    return url[:i], url[i+1:]

def _splitnetloc(url, start=0):
    delim = len(url)   # position of end of domain part of url, default is end
    for c in '/?#':    # look for delimiters; the order is NOT important
        wdelim = url.find(c, start)        # find first of this delim
        if wdelim >= 0:                    # if found
            delim = min(delim, wdelim)     # use earliest delim position
    return url[start:delim], url[delim:]   # return (domain, rest)

def _checknetloc(netloc):
    if not netloc or not isinstance(netloc, unicode):
        return
    # looking for characters like \u2100 that expand to 'a/c'
    # IDNA uses NFKC equivalence, so normalize for this check
    import unicodedata
    n = netloc.rpartition('@')[2] # ignore anything to the left of '@'
    n = n.replace(':', '')        # ignore characters already included
    n = n.replace('#', '')        # but not the surrounding text
    n = n.replace('?', '')
    netloc2 = unicodedata.normalize('NFKC', n)
    if n == netloc2:
        return
    for c in '/?#@:':
        if c in netloc2:
            raise ValueError("netloc '" + netloc + "' contains invalid " +
                             "characters under NFKC normalization")

def urlsplit(url, scheme='', allow_fragments=True):
    """Parse a URL into 5 components:
    <scheme>://<netloc>/<path>?<query>#<fragment>
    Return a 5-tuple: (scheme, netloc, path, query, fragment).
    Note that we don't break the components up in smaller bits
    (e.g. netloc is a single string) and we don't expand % escapes."""
    allow_fragments = bool(allow_fragments)
    key = url, scheme, allow_fragments, type(url), type(scheme)
    cached = _parse_cache.get(key, None)
    if cached:
        return cached
    if len(_parse_cache) >= MAX_CACHE_SIZE: # avoid runaway growth
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,17 +171,17 @@
     # looking for characters like \u2100 that expand to 'a/c'
     # IDNA uses NFKC equivalence, so normalize for this check
     import unicodedata
-    n = netloc.rpartition('@')[2] # ignore anything to the left of '@'
-    n = n.replace(':', '')        # ignore characters already included
-    n = n.replace('#', '')        # but not the surrounding text
-    n = n.replace('?', '')
+    n = netloc.replace(u'@', u'') # ignore characters already included
+    n = n.replace(u':', u'')      # but not the surrounding text
+    n = n.replace(u'#', u'')
+    n = n.replace(u'?', u'')
     netloc2 = unicodedata.normalize('NFKC', n)
     if n == netloc2:
         return
     for c in '/?#@:':
         if c in netloc2:
-            raise ValueError("netloc '" + netloc + "' contains invalid " +
-                             "characters under NFKC normalization")
+            raise ValueError(u"netloc '" + netloc + u"' contains invalid " +
+                             u"characters under NFKC normalization")
 
 def urlsplit(url, scheme='', allow_fragments=True):
     """Parse a URL into 5 components:
```
