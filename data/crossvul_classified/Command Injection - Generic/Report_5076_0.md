# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in python
**Pair ID:** 5076_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5076_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```python
Lines 1-28 of the vulnerable file.

#!/usr/bin/python

import dbus
import dbus.service
import dbus.mainloop.glib
import gobject
import slip.dbus.service
from slip.dbus import polkit
import os
class RunFix(slip.dbus.service.Object):
    default_polkit_auth_required = "org.fedoraproject.setroubleshootfixit.write"
    def __init__ (self, *p, **k):
        super(RunFix, self).__init__(*p, **k)
        
    @dbus.service.method ("org.fedoraproject.SetroubleshootFixit", in_signature='ss', out_signature='s')
    def run_fix(self, local_id, analysis_id):
        import commands
        command = "sealert -f %s -P %s" % ( local_id, analysis_id)
        return commands.getoutput(command)

if __name__ == "__main__":
    mainloop = gobject.MainLoop ()
    dbus.mainloop.glib.DBusGMainLoop (set_as_default=True)
    system_bus = dbus.SystemBus ()
    name = dbus.service.BusName("org.fedoraproject.SetroubleshootFixit", system_bus)
    object = RunFix(system_bus, "/org/fedoraproject/SetroubleshootFixit/object")
    slip.dbus.service.set_mainloop (mainloop)
    mainloop.run ()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,9 +14,9 @@
         
     @dbus.service.method ("org.fedoraproject.SetroubleshootFixit", in_signature='ss', out_signature='s')
     def run_fix(self, local_id, analysis_id):
-        import commands
-        command = "sealert -f %s -P %s" % ( local_id, analysis_id)
-        return commands.getoutput(command)
+        import subprocess
+        command = ["sealert", "-f", local_id, "-P", analysis_id]
+        return subprocess.check_output(command, universal_newlines=True)
 
 if __name__ == "__main__":
     mainloop = gobject.MainLoop ()
```
