# CrossVul Fix Pair: Cryptographic Issues in python
**Pair ID:** 546_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `546_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```python
Lines 370-410 of the vulnerable file.

    HTTP_QUERY_VARS = {'address': 'E-mail address'}

    def command(self):
        args = list(self.args)
        if len(args) > 0:
            addr = args[0]
        else:
            addr = self.data.get("address", None)

        if addr is None:
            return self._error("Must supply e-mail address", None)

        res = self._gnupg().address_to_keys(addr)
        return self._success("Searched for keys for e-mail address", res)


class GPGKeyListSecret(Command):
    """List Secret GPG Keys"""
    ORDER = ('', 0)
    SYNOPSIS = (None, 'crypto/gpg/keylist/secret',
                'crypto/gpg/keylist/secret', '<address>')
    HTTP_CALLABLE = ('GET', )

    def command(self):
        res = self._gnupg().list_secret_keys()
        return self._success("Searched for secret keys", res)


class GPGUsageStatistics(Search):
    """Get usage statistics from mail, given an address"""
    ORDER = ('', 0)
    SYNOPSIS = (None, 'crypto/gpg/statistics',
                'crypto/gpg/statistics', '<address>')
    HTTP_CALLABLE = ('GET', )
    HTTP_QUERY_VARS = {'address': 'E-mail address'}
    COMMAND_CACHE_TTL = 0

    class CommandResult(Command.CommandResult):
        def __init__(self, *args, **kwargs):
            Command.CommandResult.__init__(self, *args, **kwargs)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -387,11 +387,24 @@
     """List Secret GPG Keys"""
     ORDER = ('', 0)
     SYNOPSIS = (None, 'crypto/gpg/keylist/secret',
-                'crypto/gpg/keylist/secret', '<address>')
+                                    'crypto/gpg/keylist/secret', '[<check>]')
     HTTP_CALLABLE = ('GET', )
-
-    def command(self):
-        res = self._gnupg().list_secret_keys()
+    HTTP_QUERY_VARS = {'check': 'True to omit disabled, expired, revoked keys'}
+
+    def command(self):
+        args = list(self.args)
+        if len(args) > 0:
+            check = args[0]
+        else:
+            check = self.data.get('check', '')
+        check = 'True' in check
+        
+        all = self._gnupg().list_secret_keys()
+        if check:
+            res = {fprint : all[fprint] for fprint in all
+                if not (all[fprint]['revoked'] or all[fprint]['disabled'])}
+        else:
+            res = all
         return self._success("Searched for secret keys", res)
 
 
```
