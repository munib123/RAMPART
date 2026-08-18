# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 49_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `49_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 396-436 of the vulnerable file.

    gid = _get_gid(group)

    def _set_uid_gid(tarinfo):
        if gid is not None:
            tarinfo.gid = gid
            tarinfo.gname = group
        if uid is not None:
            tarinfo.uid = uid
            tarinfo.uname = owner
        return tarinfo

    if not dry_run:
        tar = tarfile.open(archive_name, 'w|%s' % tar_compression)
        try:
            tar.add(base_dir, filter=_set_uid_gid)
        finally:
            tar.close()

    return archive_name

def _call_external_zip(base_dir, zip_filename, verbose=False, dry_run=False):
    # XXX see if we want to keep an external call here
    if verbose:
        zipoptions = "-r"
    else:
        zipoptions = "-rq"
    from distutils.errors import DistutilsExecError
    from distutils.spawn import spawn
    try:
        spawn(["zip", zipoptions, zip_filename, base_dir], dry_run=dry_run)
    except DistutilsExecError:
        # XXX really should distinguish between "couldn't find
        # external 'zip' command" and "zip failed".
        raise ExecError, \
            ("unable to create zip file '%s': "
            "could neither import the 'zipfile' module nor "
            "find a standalone zip utility") % zip_filename

def _make_zipfile(base_name, base_dir, verbose=0, dry_run=0, logger=None):
    """Create a zip file from all the files under 'base_dir'.

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -413,17 +413,21 @@
 
     return archive_name
 
-def _call_external_zip(base_dir, zip_filename, verbose=False, dry_run=False):
+def _call_external_zip(base_dir, zip_filename, verbose, dry_run, logger):
     # XXX see if we want to keep an external call here
     if verbose:
         zipoptions = "-r"
     else:
         zipoptions = "-rq"
-    from distutils.errors import DistutilsExecError
-    from distutils.spawn import spawn
-    try:
-        spawn(["zip", zipoptions, zip_filename, base_dir], dry_run=dry_run)
-    except DistutilsExecError:
+    cmd = ["zip", zipoptions, zip_filename, base_dir]
+    if logger is not None:
+        logger.info(' '.join(cmd))
+    if dry_run:
+        return
+    import subprocess
+    try:
+        subprocess.check_call(cmd)
+    except subprocess.CalledProcessError:
         # XXX really should distinguish between "couldn't find
         # external 'zip' command" and "zip failed".
         raise ExecError, \
@@ -458,7 +462,7 @@
         zipfile = None
 
     if zipfile is None:
-        _call_external_zip(base_dir, zip_filename, verbose, dry_run)
+        _call_external_zip(base_dir, zip_filename, verbose, dry_run, logger)
     else:
         if logger is not None:
             logger.info("creating '%s' and adding '%s' to it",
```
