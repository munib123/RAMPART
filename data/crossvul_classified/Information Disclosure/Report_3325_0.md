# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 3325_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3325_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 770-825 of the vulnerable file.

                return fnd
        return fnd

    def get_file(self,
                 path,
                 dest='',
                 makedirs=False,
                 saltenv='base',
                 gzip=None,
                 cachedir=None):
        '''
        Copies a file from the local files directory into :param:`dest`
        gzip compression settings are ignored for local files
        '''
        path = self._check_proto(path)
        fnd = self._find_file(path, saltenv)
        fnd_path = fnd.get('path')
        if not fnd_path:
            return ''

        try:
            fnd_mode = fnd.get('stat', [])[0]
        except (IndexError, TypeError):
            fnd_mode = None

        if not salt.utils.is_windows():
            if fnd_mode is not None:
                try:
                    if os.stat(dest).st_mode != fnd_mode:
                        try:
                            os.chmod(dest, fnd_mode)
                        except OSError as exc:
                            log.warning('Failed to chmod %s: %s', dest, exc)
                except Exception:
                    pass

        return fnd_path

    def file_list(self, saltenv='base', prefix=''):
        '''
        Return a list of files in the given environment
        with optional relative prefix path to limit directory traversal
        '''
        ret = []
        if saltenv not in self.opts['file_roots']:
            return ret
        prefix = prefix.strip('/')
        for path in self.opts['file_roots'][saltenv]:
            for root, dirs, files in os.walk(
                os.path.join(path, prefix), followlinks=True
            ):
                # Don't walk any directories that match file_ignore_regex or glob
                dirs[:] = [d for d in dirs if not salt.fileserver.is_file_ignored(self.opts, d)]
                for fname in files:
                    relpath = os.path.relpath(os.path.join(root, fname), path)
                    ret.append(sdecode(relpath))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -787,22 +787,6 @@
         if not fnd_path:
             return ''
 
-        try:
-            fnd_mode = fnd.get('stat', [])[0]
-        except (IndexError, TypeError):
-            fnd_mode = None
-
-        if not salt.utils.is_windows():
-            if fnd_mode is not None:
-                try:
-                    if os.stat(dest).st_mode != fnd_mode:
-                        try:
-                            os.chmod(dest, fnd_mode)
-                        except OSError as exc:
-                            log.warning('Failed to chmod %s: %s', dest, exc)
-                except Exception:
-                    pass
-
         return fnd_path
 
     def file_list(self, saltenv='base', prefix=''):
@@ -1054,47 +1038,7 @@
                 mode_local = None
 
             if hash_local == hash_server:
-                if not salt.utils.is_windows():
-                    if mode_server is None:
-                        log.debug('No file mode available for \'%s\'', path)
-                    elif mode_local is None:
-                        log.debug(
-                            'No file mode available for \'%s\'',
-                            dest2check
-                        )
-                    else:
-                        if mode_server == mode_local:
-                            log.info(
-                                'Fetching file from saltenv \'%s\', '
-                                '** skipped ** latest already in cache '
-                                '\'%s\', mode up-to-date', saltenv, path
-                            )
-                        else:
-                            try:
-                                os.chmod(dest2check, mode_server)
-                                log.info(
-                                    'Fetching file from saltenv \'%s\', '
-                                    '** updated ** latest already in cache, '
-                                    '\'%s\', mode updated from %s to %s',
-                                    saltenv,
-                                    path,
-                                    salt.utils.st_mode_to_octal(mode_local),
-                                    salt.utils.st_mode_to_octal(mode_server)
-                                )
-                            except OSError as exc:
-                                log.warning(
-                                    'Failed to chmod %s: %s', dest2check, exc
-                                )
-                    # We may not have been able to check/set the mode, but we
-                    # don't want to re-download the file because of a failure
-                    # in mode checking. Return the cached path.
-                    return dest2check
-                else:
-                    log.info(
-                        'Fetching file from saltenv \'%s\', ** skipped ** '
-                        'latest already in cache \'%s\'', saltenv, path
-                    )
-                    return dest2check
+                return dest2check
 
         log.debug(
             'Fetching file from saltenv \'%s\', ** attempting ** \'%s\'',
@@ -1211,23 +1155,6 @@
                 saltenv, path
             )
 
-        if not salt.utils.is_windows():
-            if mode_server is not None:
-                try:
-                    if os.stat(dest).st_mode != mode_server:
-                        try:
-                            os.chmod(dest, mode_server)
-                            log.info(
-                                'Fetching file from saltenv \'%s\', '
-                                '** done ** \'%s\', mode set to %s',
-                                saltenv,
-                                path,
-                                salt.utils.st_mode_to_octal(mode_server)
-                            )
-                        except OSError:
-                            log.warning('Failed to chmod %s: %s', dest, exc)
-                except OSError:
-                    pass
         return dest
 
     def file_list(self, saltenv='base', prefix=''):
```
