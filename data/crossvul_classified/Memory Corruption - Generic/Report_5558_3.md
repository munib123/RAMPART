# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in python
**Pair ID:** 5558_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5558_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```python
Lines 156-193 of the vulnerable file.



class UserNotFound(NotFound):
    """Could not find user: %(user_id)s"""


class GroupNotFound(NotFound):
    """Could not find group: %(group_id)s"""


class Conflict(Error):
    """Conflict occurred attempting to store %(type)s.

    %(details)s

    """
    code = 409
    title = 'Conflict'


class UnexpectedError(Error):
    """An unexpected error prevented the server from fulfilling your request.

    %(exception)s

    """
    code = 500
    title = 'Internal Server Error'


class MalformedEndpoint(UnexpectedError):
    """Malformed endpoint URL (see ERROR log for details): %(endpoint)s"""


class NotImplemented(Error):
    """The action you have requested has not been implemented."""
    code = 501
    title = 'Not Implemented'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -173,6 +173,12 @@
     title = 'Conflict'
 
 
+class RequestTooLarge(Error):
+    """Request is too large."""
+    code = 413
+    title = 'Request is too large.'
+
+
 class UnexpectedError(Error):
     """An unexpected error prevented the server from fulfilling your request.
 
```
