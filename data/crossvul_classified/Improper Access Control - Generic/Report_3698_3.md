# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 3698_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3698_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 297-337 of the vulnerable file.

    in a different way to inject_data
    """
    if key:
        _inject_key_into_fs(key, fs, execute=execute)
    if net:
        _inject_net_into_fs(net, fs, execute=execute)
    if metadata:
        _inject_metadata_into_fs(metadata, fs, execute=execute)
    if admin_password:
        _inject_admin_password_into_fs(admin_password, fs, execute=execute)


def _join_and_check_path_within_fs(fs, *args):
    '''os.path.join() with safety check for injected file paths.

    Join the supplied path components and make sure that the
    resulting path we are injecting into is within the
    mounted guest fs.  Trying to be clever and specifying a
    path with '..' in it will hit this safeguard.
    '''
    absolute_path = os.path.realpath(os.path.join(fs, *args))
    if not absolute_path.startswith(os.path.realpath(fs) + '/'):
        raise exception.Invalid(_('injected file path not valid'))
    return absolute_path


def _inject_file_into_fs(fs, path, contents, append=False):
    absolute_path = _join_and_check_path_within_fs(fs, path.lstrip('/'))

    parent_dir = os.path.dirname(absolute_path)
    utils.execute('mkdir', '-p', parent_dir, run_as_root=True)

    args = []
    if append:
        args.append('-a')
    args.append(absolute_path)

    kwargs = dict(process_input=contents, run_as_root=True)

    utils.execute('tee', *args, **kwargs)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -314,7 +314,9 @@
     mounted guest fs.  Trying to be clever and specifying a
     path with '..' in it will hit this safeguard.
     '''
-    absolute_path = os.path.realpath(os.path.join(fs, *args))
+    absolute_path, _err = utils.execute('readlink', '-nm',
+                                        os.path.join(fs, *args),
+                                        run_as_root=True)
     if not absolute_path.startswith(os.path.realpath(fs) + '/'):
         raise exception.Invalid(_('injected file path not valid'))
     return absolute_path
```
