# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in python
**Pair ID:** 5860_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5860_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```python
Lines 138-178 of the vulnerable file.


        if fetch:
            tmp = open(tmpnam, 'w+b')

            # Grab the HTTP info / prepare to read.
            response = urllib.request.urlopen(href)

            # Grab in kilobyte chunks to avoid wasting memory on something
            # that's going to be immediately written to disk.

            while True:
                r = response.read(1024)
                if not r:
                    break
                tmp.write(r)

            response.close()
            tmp.close()

            href = tmpnam

        # A lot of programs don't appreciate
        # having their fds closed, so instead
        # we dup them to /dev/null.

        fd = os.open("/dev/null", os.O_RDWR)
        os.dup2(fd, sys.stderr.fileno())

        if not text:
            os.setpgid(os.getpid(), os.getpid())
            os.dup2(fd, sys.stdout.fileno())

        if "%u" in path:
            path = path.replace("%u", href)
        elif href:
            path = path + " " + href

        os.execv("/bin/sh", ["/bin/sh", "-c", path])

        # Just in case.
        sys.exit(0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,6 +155,11 @@
             tmp.close()
 
             href = tmpnam
+
+        # Make sure that we quote href such that malicious URLs like
+        # "http://example.com & rm -rf ~/" won't be interpreted by the shell.
+
+        href = shlex.quote(href)
 
         # A lot of programs don't appreciate
         # having their fds closed, so instead
```
