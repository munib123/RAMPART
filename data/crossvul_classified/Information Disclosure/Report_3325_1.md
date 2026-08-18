# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 3325_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3325_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 614-654 of the vulnerable file.


def hash_file(path, saltenv='base'):
    '''
    Return the hash of a file, to get the hash of a file on the
    salt master file server prepend the path with salt://<file on server>
    otherwise, prepend the file with / for a local file.

    CLI Example:

    .. code-block:: bash

        salt '*' cp.hash_file salt://path/to/file
    '''
    path, senv = salt.utils.url.split_env(path)
    if senv:
        saltenv = senv

    return _client().hash_file(path, saltenv)


def push(path, keep_symlinks=False, upload_path=None, remove_source=False):
    '''
    WARNING Files pushed to the master will have global read permissions..

    Push a file from the minion up to the master, the file will be saved to
    the salt master in the master's minion files cachedir
    (defaults to ``/var/cache/salt/master/minions/minion-id/files``)

    Since this feature allows a minion to push a file up to the master server
    it is disabled by default for security purposes. To enable, set
    ``file_recv`` to ``True`` in the master configuration file, and restart the
    master.

    keep_symlinks
        Keep the path value without resolving its canonical form

    upload_path
        Provide a different path inside the master's minion files cachedir

    remove_source
        Remove the source file on the minion
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -629,6 +629,28 @@
         saltenv = senv
 
     return _client().hash_file(path, saltenv)
+
+
+def stat_file(path, saltenv='base', octal=True):
+    '''
+    Return the permissions of a file, to get the permissions of a file on the
+    salt master file server prepend the path with salt://<file on server>
+    otherwise, prepend the file with / for a local file.
+
+    CLI Example:
+
+    .. code-block:: bash
+
+        salt '*' cp.stat_file salt://path/to/file
+    '''
+    path, senv = salt.utils.url.split_env(path)
+    if senv:
+        saltenv = senv
+
+    stat = _client().hash_and_stat_file(path, saltenv)[1]
+    if stat is None:
+        return stat
+    return salt.utils.st_mode_to_octal(stat[0]) if octal is True else stat[0]
 
 
 def push(path, keep_symlinks=False, upload_path=None, remove_source=False):
```
