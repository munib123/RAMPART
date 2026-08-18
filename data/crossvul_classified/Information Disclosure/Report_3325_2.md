# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 3325_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3325_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 4332-4372 of the vulnerable file.

            name,
            template,
            source,
            source_hash,
            source_hash_name,
            user,
            group,
            mode,
            saltenv,
            context,
            defaults,
            skip_verify,
            **kwargs)
        if comments:
            __clean_tmp(sfn)
            return False, comments
        if sfn and source and keep_mode:
            if _urlparse(source).scheme in ('salt', 'file') \
                    or source.startswith('/'):
                try:
                    mode = salt.utils.st_mode_to_octal(os.stat(sfn).st_mode)
                except Exception as exc:
                    log.warning('Unable to stat %s: %s', sfn, exc)
    changes = check_file_meta(name, sfn, source, source_sum, user,
                              group, mode, saltenv, contents)
    __clean_tmp(sfn)
    return changes


def check_file_meta(
        name,
        sfn,
        source,
        source_sum,
        user,
        group,
        mode,
        saltenv,
        contents=None):
    '''
    Check for the changes in the file metadata.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4349,7 +4349,7 @@
             if _urlparse(source).scheme in ('salt', 'file') \
                     or source.startswith('/'):
                 try:
-                    mode = salt.utils.st_mode_to_octal(os.stat(sfn).st_mode)
+                    mode = __salt__['cp.stat_file'](source, saltenv=saltenv, octal=True)
                 except Exception as exc:
                     log.warning('Unable to stat %s: %s', sfn, exc)
     changes = check_file_meta(name, sfn, source, source_sum, user,
@@ -4607,6 +4607,13 @@
         a local file on the minion), the mode of the destination file will be
         set to the mode of the source file.
 
+        .. note:: keep_mode does not work with salt-ssh.
+
+            As a consequence of how the files are transfered to the minion, and
+            the inability to connect back to the master with salt-ssh, salt is
+            unable to stat the file as it exists on the fileserver and thus
+            cannot mirror the mode on the salt-ssh minion
+
     CLI Example:
 
     .. code-block:: bash
@@ -4641,7 +4648,7 @@
             if _urlparse(source).scheme in ('salt', 'file') \
                     or source.startswith('/'):
                 try:
-                    mode = salt.utils.st_mode_to_octal(os.stat(sfn).st_mode)
+                    mode = __salt__['cp.stat_file'](source, saltenv=saltenv, octal=True)
                 except Exception as exc:
                     log.warning('Unable to stat %s: %s', sfn, exc)
 
```
