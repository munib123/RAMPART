# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 3481_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3481_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 30-70 of the vulnerable file.

    in the background as daemon process.  The only requirement 
    is for the derived class to implement a main_loop() method.
    See Test class below for an example.

    The following command line operations are provided to support
    typical /etc/init.d startup/shutdown on Unix systems:

        start | stop | restart

    In addition, a daemonized program can be called with arguments:

        status  - check if process is still running

        debug   - run the program in non-daemon mode for testing

    Note: Since Daemonizer uses fork(), it will not work on non-Unix
    systems.
    """
    def __init__(self, pidfile=None):
        if not pidfile:
            self.pidfile = "/tmp/%s.pid" % self.__class__.__name__.lower()
        else:
            self.pidfile = pidfile

    def become_daemon(self, root_dir='/'):
        if os.fork() != 0:  # launch child and ...
            os._exit(0)  # kill off parent
        os.setsid()
        os.chdir(root_dir)
        os.umask(0)
        if os.fork() != 0: # fork again so we are not a session leader
            os._exit(0)
        sys.stdin.close()
        sys.__stdin__ = sys.stdin
        sys.stdout.close()
        sys.stdout = sys.__stdout__ = _NullDevice()
        sys.stderr.close()
        sys.stderr = sys.__stderr__ = _NullDevice()
        for fd in range(1024):
            try:
                os.close(fd)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,7 +47,9 @@
     """
     def __init__(self, pidfile=None):
         if not pidfile:
-            self.pidfile = "/tmp/%s.pid" % self.__class__.__name__.lower()
+            # PID file moved out of /tmp to avoid security vulnerability
+            # changed by Debian maintainer per Debian bug #631912
+            self.pidfile = "/var/run/pyro-%s.pid" % self.__class__.__name__.lower()
         else:
             self.pidfile = pidfile
 
@@ -121,12 +123,16 @@
 
     def process_command_line(self, argv, verbose=1):
         usage = "usage:  %s  start | stop | restart | status | debug " \
+                "[--pidfile=...] " \
                 "(run as non-daemon)" % os.path.basename(argv[0])
         if len(argv) < 2:
             print usage
             raise SystemExit
         else:
             operation = argv[1]
+            if len(argv) > 2 and argv[2].startswith('--pidfile=') and \
+                len(argv[2]) > len('--pidfile='):
+                self.pidfile = argv[2][len('--pidfile='):]
         pid = self.get_pid()
         if operation == 'status':
             if self.is_process_running():
```
