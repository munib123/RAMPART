# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1915_9
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_9`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 108-148 of the vulnerable file.

        if ip_whitelist is None or ip_address not in ip_whitelist:
            return True
    return False


_EPSILON = 0.00000001


def _make_scheduler(reactor):
    """Makes a schedular suitable for a Cooperator using the given reactor.

    (This is effectively just a copy from `twisted.internet.task`)
    """

    def _scheduler(x):
        return reactor.callLater(_EPSILON, x)

    return _scheduler


class IPBlacklistingResolver:
    """
    A proxy for reactor.nameResolver which only produces non-blacklisted IP
    addresses, preventing DNS rebinding attacks on URL preview.
    """

    def __init__(
        self,
        reactor: IReactorPluggableNameResolver,
        ip_whitelist: Optional[IPSet],
        ip_blacklist: IPSet,
    ):
        """
        Args:
            reactor: The twisted reactor.
            ip_whitelist: IP addresses to allow.
            ip_blacklist: IP addresses to disallow.
        """
        self._reactor = reactor
        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -125,7 +125,7 @@
     return _scheduler
 
 
-class IPBlacklistingResolver:
+class _IPBlacklistingResolver:
     """
     A proxy for reactor.nameResolver which only produces non-blacklisted IP
     addresses, preventing DNS rebinding attacks on URL preview.
@@ -197,6 +197,35 @@
         )
 
         return r
+
+
+@implementer(IReactorPluggableNameResolver)
+class BlacklistingReactorWrapper:
+    """
+    A Reactor wrapper which will prevent DNS resolution to blacklisted IP
+    addresses, to prevent DNS rebinding.
+    """
+
+    def __init__(
+        self,
+        reactor: IReactorPluggableNameResolver,
+        ip_whitelist: Optional[IPSet],
+        ip_blacklist: IPSet,
+    ):
+        self._reactor = reactor
+
+        # We need to use a DNS resolver which filters out blacklisted IP
+        # addresses, to prevent DNS rebinding.
+        self._nameResolver = _IPBlacklistingResolver(
+            self._reactor, ip_whitelist, ip_blacklist
+        )
+
+    def __getattr__(self, attr: str) -> Any:
+        # Passthrough to the real reactor except for the DNS resolver.
+        if attr == "nameResolver":
+            return self._nameResolver
+        else:
+            return getattr(self._reactor, attr)
 
 
 class BlacklistingAgentWrapper(Agent):
@@ -292,22 +321,11 @@
         self.user_agent = self.user_agent.encode("ascii")
 
         if self._ip_blacklist:
-            real_reactor = hs.get_reactor()
             # If we have an IP blacklist, we need to use a DNS resolver which
             # filters out blacklisted IP addresses, to prevent DNS rebinding.
-            nameResolver = IPBlacklistingResolver(
-                real_reactor, self._ip_whitelist, self._ip_blacklist
+            self.reactor = BlacklistingReactorWrapper(
+                hs.get_reactor(), self._ip_whitelist, self._ip_blacklist
             )
-
-            @implementer(IReactorPluggableNameResolver)
-            class Reactor:
-                def __getattr__(_self, attr):
-                    if attr == "nameResolver":
-                        return nameResolver
-                    else:
-                        return getattr(real_reactor, attr)
-
-            self.reactor = Reactor()
         else:
             self.reactor = hs.get_reactor()
 
```
