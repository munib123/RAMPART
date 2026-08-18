# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in python
**Pair ID:** 3284_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3284_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```python
Lines 265-309 of the vulnerable file.

        # from jockey
        """
        Verify that sender has a given PolicyKit privilege.

        sender is the sender's (private) D-BUS name, such as ":1:42"
        (sender_keyword in @dbus.service.methods). conn is
        the dbus.Connection object (connection_keyword in
        @dbus.service.methods). privilege is the PolicyKit privilege string.

        This method returns if the caller is privileged, and otherwise throws a
        PermissionDeniedByPolicy exception.
        """
        if sender is None and conn is None:
            # called locally, not through D-BUS
            return
        if not self.enforce_polkit:
            # that happens for testing purposes when running on the session
            # bus, and it does not make sense to restrict operations here
            return

        info = SenderInfo(sender, conn)

        # get peer PID
        pid = info.connectionPid()

        # query PolicyKit
        self._initPolkit()
        try:
            # we don't need is_challenge return here, since we call with AllowUserInteraction
            (is_auth, _, details) = self.polkit.CheckAuthorization(
                    ('unix-process', {'pid': dbus.UInt32(pid, variant_level=1),
                    'start-time': dbus.UInt64(0, variant_level=1)}),
                    privilege, {'': ''}, dbus.UInt32(1), '', timeout=3000)
        except dbus.DBusException as e:
            if e._dbus_error_name == 'org.freedesktop.DBus.Error.ServiceUnknown':
                # polkitd timed out, connect again
                self.polkit = None
                return self._checkPolkitPrivilege(sender, conn, privilege)
            else:
                raise

        if not is_auth:
            raise PermissionDeniedByPolicy(privilege)

class SenderInfo(object):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -282,18 +282,12 @@
             # bus, and it does not make sense to restrict operations here
             return
 
-        info = SenderInfo(sender, conn)
-
-        # get peer PID
-        pid = info.connectionPid()
-
         # query PolicyKit
         self._initPolkit()
         try:
             # we don't need is_challenge return here, since we call with AllowUserInteraction
             (is_auth, _, details) = self.polkit.CheckAuthorization(
-                    ('unix-process', {'pid': dbus.UInt32(pid, variant_level=1),
-                    'start-time': dbus.UInt64(0, variant_level=1)}),
+                    ('system-bus-name', {'name': dbus.String(sender, variant_level=1)}),
                     privilege, {'': ''}, dbus.UInt32(1), '', timeout=3000)
         except dbus.DBusException as e:
             if e._dbus_error_name == 'org.freedesktop.DBus.Error.ServiceUnknown':
```
