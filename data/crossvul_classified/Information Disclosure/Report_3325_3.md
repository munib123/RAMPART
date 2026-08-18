# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 3325_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3325_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 1318-1358 of the vulnerable file.

    group
        The group ownership set for the file, this defaults to the group salt
        is running as on the minion On Windows, this is ignored

    mode
        The permissions to set on this file, e.g. ``644``, ``0775``, or ``4664``.

        The default mode for new files and directories corresponds umask of salt
        process. For existing files and directories it's not enforced.

        .. note::
            This option is **not** supported on Windows.

        .. versionchanged:: 2016.11.0
            This option can be set to ``keep``, and Salt will keep the mode
            from the Salt fileserver. This is only supported when the
            ``source`` URL begins with ``salt://``, or for files local to the
            minion. Because the ``source`` option cannot be used with any of
            the ``contents`` options, setting the ``mode`` to ``keep`` is also
            incompatible with the ``contents`` options.

    template
        If this setting is applied, the named templating engine will be used to
        render the downloaded file. The following templates are supported:

        - :mod:`cheetah<salt.renderers.cheetah>`
        - :mod:`genshi<salt.renderers.genshi>`
        - :mod:`jinja<salt.renderers.jinja>`
        - :mod:`mako<salt.renderers.mako>`
        - :mod:`py<salt.renderers.py>`
        - :mod:`wempy<salt.renderers.wempy>`

    makedirs : False
        If set to ``True``, then the parent directories will be created to
        facilitate the creation of the named file. If ``False``, and the parent
        directory of the destination file doesn't exist, the state will fail.

    dir_mode
        If directories are to be created, passing this option specifies the
        permissions for those directories. If this is not set, directories
        will be assigned permissions by adding the execute bit to the mode of
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1335,6 +1335,13 @@
             minion. Because the ``source`` option cannot be used with any of
             the ``contents`` options, setting the ``mode`` to ``keep`` is also
             incompatible with the ``contents`` options.
+
+        .. note:: keep does not work with salt-ssh.
+
+            As a consequence of how the files are transfered to the minion, and
+            the inability to connect back to the master with salt-ssh, salt is
+            unable to stat the file as it exists on the fileserver and thus
+            cannot mirror the mode on the salt-ssh minion
 
     template
         If this setting is applied, the named templating engine will be used to
```
