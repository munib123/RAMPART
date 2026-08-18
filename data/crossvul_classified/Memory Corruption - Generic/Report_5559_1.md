# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 5559_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5559_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 26-66 of the vulnerable file.

    title = None

    def __init__(self, message=None, **kwargs):
        """Use the doc string as the error message by default."""
        message = message or self.__doc__ % kwargs
        super(Error, self).__init__(message)

    def __str__(self):
        """Cleans up line breaks and indentation from doc strings."""
        string = super(Error, self).__str__()
        string = re.sub('[ \n]+', ' ', string)
        string = string.strip()
        return string


class ValidationError(Error):
    """Expecting to find %(attribute)s in %(target)s.

    The server could not comply with the request since it is either malformed
    or otherwise incorrect.

    The client is assumed to be in error.

    """
    code = 400
    title = 'Bad Request'


class Unauthorized(Error):
    """The request you have made requires authentication."""
    code = 401
    title = 'Not Authorized'


class Forbidden(Error):
    """You are not authorized to perform the requested action."""
    code = 403
    title = 'Not Authorized'


class ForbiddenAction(Forbidden):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,19 @@
 
     The server could not comply with the request since it is either malformed
     or otherwise incorrect.
+
+    The client is assumed to be in error.
+
+    """
+    code = 400
+    title = 'Bad Request'
+
+
+class ValidationSizeError(Error):
+    """Request attribute %(attribute)s must be less than or equal to %(size)i.
+
+    The server could not comply with the request because the attribute
+    size is invalid (too large).
 
     The client is assumed to be in error.
 
```
