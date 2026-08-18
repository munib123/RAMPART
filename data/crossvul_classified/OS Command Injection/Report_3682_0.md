# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 3682_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3682_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 1-22 of the vulnerable file.

import os
import Bcfg2.Server.Plugin


def async_run(prog, args):
    pid = os.fork()
    if pid:
        os.waitpid(pid, 0)
    else:
        dpid = os.fork()
        if not dpid:
            os.system(" ".join([prog] + args))
        os._exit(0)


class Trigger(Bcfg2.Server.Plugin.Plugin,
              Bcfg2.Server.Plugin.Statistics):
    """Trigger is a plugin that calls external scripts (on the server)."""
    name = 'Trigger'
    __version__ = '$Id'
    __author__ = 'bcfg-dev@mcs.anl.gov'

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,17 +1,7 @@
 import os
+import pipes
 import Bcfg2.Server.Plugin
-
-
-def async_run(prog, args):
-    pid = os.fork()
-    if pid:
-        os.waitpid(pid, 0)
-    else:
-        dpid = os.fork()
-        if not dpid:
-            os.system(" ".join([prog] + args))
-        os._exit(0)
-
+from subprocess import Popen, PIPE
 
 class Trigger(Bcfg2.Server.Plugin.Plugin,
               Bcfg2.Server.Plugin.Statistics):
@@ -30,15 +20,35 @@
                               "unloading" % self.data)
             raise Bcfg2.Server.Plugin.PluginInitError
 
+    def async_run(self, args):
+        pid = os.fork()
+        if pid:
+            os.waitpid(pid, 0)
+        else:
+            dpid = os.fork()
+            if not dpid:
+                self.debug_log("Running %s" % " ".join(pipes.quote(a)
+                                                       for a in args))
+                proc = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
+                (out, err) = proc.communicate()
+                rv = proc.wait()
+                if rv != 0:
+                    self.logger.error("Trigger: Error running %s (%s): %s" %
+                                      (args[0], rv, err))
+                elif err:
+                    self.debug_log("Trigger: Error: %s" % err)
+            os._exit(0)
+
     def process_statistics(self, metadata, _):
         args = [metadata.hostname, '-p', metadata.profile, '-g',
                 ':'.join([g for g in metadata.groups])]
+        self.debug_log("running triggers")
         for notifier in os.listdir(self.data):
+            self.debug_log("running %s" % notifier)
             if ((notifier[-1] == '~') or
                 (notifier[:2] == '.#') or
                 (notifier[-4:] == '.swp') or
                 (notifier in ['SCCS', '.svn', '4913'])):
                 continue
-            npath = self.data + '/' + notifier
-            self.logger.debug("Running %s %s" % (npath, " ".join(args)))
-            async_run(npath, args)
+            npath = os.path.join(self.data, notifier)
+            self.async_run([npath] + args)
```
