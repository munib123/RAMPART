# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4366_6
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4366_6`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 330-368 of the vulnerable file.

        elif handler:
            return guess_callback_uri(
                handler.request.protocol,
                handler.request.host,
                handler.hub.server.base_url,
            )
        else:
            raise ValueError(
                "Specify callback oauth_callback_url or give me a handler to guess with"
            )

    def get_handlers(self, app):
        return [
            (r'/oauth_login', self.login_handler),
            (r'/oauth_callback', self.callback_handler),
        ]

    async def authenticate(self, handler, data=None):
        raise NotImplementedError()


    def _deprecated_trait(self, change):
        """observer for deprecated traits"""
        old_attr = change.name
        new_attr, version = self._deprecated_aliases.get(old_attr)
        new_value = getattr(self, new_attr)
        if new_value != change.new:
            # only warn if different
            # protects backward-compatible config from warnings
            # if they set the same value under both names
            self.log.warning(
                "{cls}.{old} is deprecated in {cls} {version}, use {cls}.{new} instead".format(
                    cls=self.__class__.__name__,
                    old=old_attr,
                    new=new_attr,
                    version=version,
                )
            )
            setattr(self, new_attr, change.new)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -347,11 +347,12 @@
     async def authenticate(self, handler, data=None):
         raise NotImplementedError()
 
-
-    def _deprecated_trait(self, change):
+    _deprecated_oauth_aliases = {}
+
+    def _deprecated_oauth_trait(self, change):
         """observer for deprecated traits"""
         old_attr = change.name
-        new_attr, version = self._deprecated_aliases.get(old_attr)
+        new_attr, version = self._deprecated_oauth_aliases.get(old_attr)
         new_value = getattr(self, new_attr)
         if new_value != change.new:
             # only warn if different
@@ -366,3 +367,11 @@
                 )
             )
             setattr(self, new_attr, change.new)
+
+    def __init__(self, **kwargs):
+        # observe deprecated config names in oauthenticator
+        if self._deprecated_oauth_aliases:
+            self.observe(
+                self._deprecated_oauth_trait, names=list(self._deprecated_oauth_aliases)
+            )
+        super().__init__(**kwargs)
```
