# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in python
**Pair ID:** 5042_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5042_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```python
Lines 74-103 of the vulnerable file.


    then_text = "You need to change the label on '$FIX_TARGET_PATH'"
    do_text = """# semanage fcontext -a -t textrel_shlib_t '$FIX_TARGET_PATH'
# restorecon -v '$FIX_TARGET_PATH'"""

    def get_then_text(self, avc, args):
        if len(args) > 0:
            return self.unsafe_then_text
        return self.then_text

    def get_do_text(self, avc, args):
        if len(args) > 0:
            return self.unsafe_do_text
        return self.do_text

    def __init__(self):
        Plugin.__init__(self,__name__)
        self.set_priority(10)

    def analyze(self, avc):
        import commands
        if avc.has_any_access_in(['execmod']):
            # MATCH
            if (commands.getstatusoutput("eu-readelf -d %s | fgrep -q TEXTREL" % avc.tpath)[0] == 1):
                return self.report(("unsafe"))

            mcon = selinux.matchpathcon(avc.tpath.strip('"'), S_IFREG)[1]
            if mcon.split(":")[2] == "lib_t":
                return self.report()
        return None
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,10 +91,16 @@
         self.set_priority(10)
 
     def analyze(self, avc):
-        import commands
+        import subprocess
         if avc.has_any_access_in(['execmod']):
             # MATCH
-            if (commands.getstatusoutput("eu-readelf -d %s | fgrep -q TEXTREL" % avc.tpath)[0] == 1):
+            # from https://docs.python.org/2.7/library/subprocess.html#replacing-shell-pipeline
+            p1 = subprocess.Popen(['eu-readelf', '-d', avc.tpath], stdout=subprocess.PIPE)
+            p2 = subprocess.Popen(["fgrep", "-q", "TEXTREL"], stdin=p1.stdout, stdout=subprocess.PIPE)
+            p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
+            p1.wait()
+            p2.wait()
+            if p2.returncode == 1:
                 return self.report(("unsafe"))
 
             mcon = selinux.matchpathcon(avc.tpath.strip('"'), S_IFREG)[1]
```
