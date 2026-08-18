# CrossVul Fix Pair: Insufficient Entropy in python
**Pair ID:** 997_1
**Vulnerability Class:** Insufficient Entropy
**CWE:** CWE-331
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `997_1`)

## Vulnerability Information & PoC

## Description
Insufficient Entropy - The product uses an algorithm or scheme that produces insufficient entropy, leaving patterns or clusters of values that are more likely to occur than others.

## Vulnerable Code
```python
Lines 50-90 of the vulnerable file.

# A week
PIN_TIME = 60 * 60 * 24 * 7


def hash_pin(pin):
    if isinstance(pin, text_type):
        pin = pin.encode("utf-8", "replace")
    return hashlib.md5(pin + b"shittysalt").hexdigest()[:12]


_machine_id = None


def get_machine_id():
    global _machine_id
    rv = _machine_id
    if rv is not None:
        return rv

    def _generate():
        # Potential sources of secret information on linux.  The machine-id
        # is stable across boots, the boot id is not
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    return f.readline().strip()
            except IOError:
                continue

        # On OS X we can use the computer's serial number assuming that
        # ioreg exists and can spit out that information.
        try:
            # Also catch import errors: subprocess may not be available, e.g.
            # Google App Engine
            # See https://github.com/pallets/werkzeug/issues/925
            from subprocess import Popen, PIPE

            dump = Popen(
                ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"], stdout=PIPE
            ).communicate()[0]
            match = re.search(b'"serial-number" = <([^>]+)', dump)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,6 +67,19 @@
         return rv
 
     def _generate():
+        # docker containers share the same machine id, get the
+        # container id instead
+        try:
+            with open("/proc/self/cgroup") as f:
+                value = f.readline()
+        except IOError:
+            pass
+        else:
+            value = value.strip().partition("/docker/")[2]
+
+            if value:
+                return value
+
         # Potential sources of secret information on linux.  The machine-id
         # is stable across boots, the boot id is not
         for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
```
