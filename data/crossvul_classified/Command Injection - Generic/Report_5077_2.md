# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in python
**Pair ID:** 5077_2
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5077_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```python
Lines 847-887 of the vulnerable file.

                             if i[0] == ("/dev/%s" % dev) or i[2] == dev:
                                 path = i[1]
                                 break
                             else:
                                 try:
                                     if dev_rdev != 0 and os.lstat(i[0]).st_rdev == dev_rdev:
                                         path = i[1]
                                         break
                                 except OSError:
                                     pass
                except TypeError:
                    path = "unknown mountpoint"
                    pass
                except OSError:
                    path = "unknown mountpoint"
                    pass

            else:
                if path.startswith("/") == False and inodestr:
                    import subprocess
                    command = "locate -b '\%s'" % path 
                    try:
                        output = subprocess.check_output(command, 
                                                         stderr=subprocess.STDOUT,
                                                         shell=True)
                        ino = int(inodestr)
                        for file in output.split("\n"):
                            try:
                                if int(os.lstat(file).st_ino) == ino:
                                    path = file
                                    break
                            except:
                                pass
                    except subprocess.CalledProcessError as e:
                        pass

        if path is not None:
            if path.startswith('/'):
                # Fully qualified path
                # map /proc/1234/ to /proc/<pid>, replacing numeric pid with <pid>
                path = self.proc_pid_instance_re.sub(r'\1<pid>\3', path)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -864,12 +864,10 @@
             else:
                 if path.startswith("/") == False and inodestr:
                     import subprocess
-                    command = "locate -b '\%s'" % path 
+                    command = ["locate", "-b", "\%s" % path]
                     try:
-                        output = subprocess.check_output(command, 
-                                                         stderr=subprocess.STDOUT,
-                                                         shell=True)
-                        ino = int(inodestr)
+                        output = subprocess.check_output(command,
+                                                         stderr=subprocess.STDOUT)
                         for file in output.split("\n"):
                             try:
                                 if int(os.lstat(file).st_ino) == ino:
```
