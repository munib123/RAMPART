# CrossVul Fix Pair: Exposure of Resource to Wrong Sphere in python
**Pair ID:** 4374_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-668
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4374_2`)

## Vulnerability Information & PoC

## Description
Exposure of Resource to Wrong Sphere - Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object.

## Vulnerable Code
```python
Lines 1-27 of the vulnerable file.

"""
Systemd service utilities.

Contains functions to start, stop & poll systemd services.
Probably not very useful outside this spawner.
"""
import asyncio
import shlex


async def start_transient_service(
    unit_name,
    cmd,
    args,
    working_dir,
    environment_variables=None,
    properties=None,
    uid=None,
    gid=None,
    slice=None,
):
    """
    Start a systemd transient service with given paramters
    """

    run_cmd = [
        'systemd-run',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,8 +4,62 @@
 Contains functions to start, stop & poll systemd services.
 Probably not very useful outside this spawner.
 """
+
 import asyncio
+import os
+import re
 import shlex
+import warnings
+
+# light validation of environment variable keys
+env_pat = re.compile("[A-Za-z_]+")
+
+RUN_ROOT = "/run"
+
+def ensure_environment_directory(environment_file_directory):
+    """Ensure directory for environment files exists and is private"""
+    # ensure directory exists
+    os.makedirs(environment_file_directory, mode=0o700, exist_ok=True)
+    # validate permissions
+    mode = os.stat(environment_file_directory).st_mode
+    if mode & 0o077:
+        warnings.warn(
+            f"Fixing permissions on environment directory {environment_file_directory}: {oct(mode)}",
+            RuntimeWarning,
+        )
+        os.chmod(environment_file_directory, 0o700)
+    else:
+        return
+    # Check again after supposedly fixing.
+    # Some filesystems can have weird issues, preventing this from having desired effect
+    mode = os.stat(environment_file_directory).st_mode
+    if mode & 0o077:
+        warnings.warn(
+            f"Bad permissions on environment directory {environment_file_directory}: {oct(mode)}",
+            RuntimeWarning,
+        )
+
+
+def make_environment_file(environment_file_directory, unit_name, environment_variables):
+    """Make a systemd environment file
+
+    - ensures environment directory exists and is private
+    - writes private environment file
+    - returns path to created environment file
+    """
+    ensure_environment_directory(environment_file_directory)
+    env_file = os.path.join(environment_file_directory, f"{unit_name}.env")
+    env_lines = []
+    for key, value in sorted(environment_variables.items()):
+        assert env_pat.match(key), f"{key} not a valid environment variable"
+        env_lines.append(f"{key}={shlex.quote(value)}")
+    env_lines.append("")  # trailing newline
+    with open(env_file, mode="w") as f:
+        # make the file itself private as well
+        os.fchmod(f.fileno(), 0o400)
+        f.write("\n".join(env_lines))
+
+    return env_file
 
 
 async def start_transient_service(
@@ -20,13 +74,31 @@
     slice=None,
 ):
     """
-    Start a systemd transient service with given paramters
+    Start a systemd transient service with given parameters
     """
 
     run_cmd = [
         'systemd-run',
         '--unit', unit_name,
     ]
+
+    if properties is None:
+        properties = {}
+    else:
+        properties = properties.copy()
+
+    # ensure there is a runtime directory where we can put our env file
+    # If already set, can be space-separated list of paths
+    runtime_directories = properties.setdefault("RuntimeDirectory", unit_name).split()
+
+    # runtime directories are always resolved relative to `/run`
+    # grab the first item, if more than one
+    runtime_dir = os.path.join(RUN_ROOT, runtime_directories[0])
+    # make runtime directories private by default
+    properties.setdefault("RuntimeDirectoryMode", "700")
+    # preserve runtime directories across restarts
+    # allows `systemctl restart` to load the env
+    properties.setdefault("RuntimeDirectoryPreserve", "restart")
 
     if properties:
         for key, value in properties.items():
@@ -37,10 +109,10 @@
                 run_cmd.append('--property={}={}'.format(key, value))
 
     if environment_variables:
-        run_cmd += [
-            '--setenv={}={}'.format(key, value)
-            for key, value in environment_variables.items()
-        ]
+        environment_file = make_environment_file(
+            runtime_dir, unit_name, environment_variables
+        )
+        run_cmd.append(f"--property=EnvironmentFile={environment_file}")
 
     # Explicitly check if uid / gid are not None, since 0 is valid value for both
     if uid is not None:
@@ -51,7 +123,7 @@
 
     if slice is not None:
         run_cmd += ['--slice={}'.format(slice)]
-    
+
     # We unfortunately have to resort to doing cd with bash, since WorkingDirectory property
     # of systemd units can't be set for transient units via systemd-run until systemd v227.
     # Centos 7 has systemd 219, and will probably never upgrade - so we need to support them.
```
