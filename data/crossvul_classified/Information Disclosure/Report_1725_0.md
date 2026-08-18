# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 1725_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1725_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 1-29 of the vulnerable file.

# -*- coding: utf-8 -*-
'''
Support for the Git SCM
'''
from __future__ import absolute_import

# Import python libs
import os
import subprocess

# Import salt libs
from salt import utils
from salt.exceptions import SaltInvocationError, CommandExecutionError
from salt.ext.six.moves.urllib.parse import urlparse as _urlparse  # pylint: disable=no-name-in-module,import-error
from salt.ext.six.moves.urllib.parse import urlunparse as _urlunparse  # pylint: disable=no-name-in-module,import-error


def __virtual__():
    '''
    Only load if git exists on the system
    '''
    return True if utils.which('git') else False


def _git_run(cmd, cwd=None, runas=None, identity=None, **kwargs):
    '''
    simple, throw an exception with the error message on an error return code.

    this function may be moved to the command module, spliced with
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 
 # Import python libs
 import os
+import re
 import subprocess
 
 # Import salt libs
@@ -62,6 +63,7 @@
                 result = __salt__['cmd.run_all'](cmd,
                                                  cwd=cwd,
                                                  runas=runas,
+                                                 output_loglevel='quiet',
                                                  env=env,
                                                  python_shell=False,
                                                  **kwargs)
@@ -73,7 +75,8 @@
             if result['retcode'] == 0:
                 return result['stdout']
             else:
-                stderrs.append(result['stderr'])
+                stderr = _remove_sensitive_data(result['stderr'])
+                stderrs.append(stderr)
 
         # we've tried all IDs and still haven't passed, so error out
         raise CommandExecutionError("\n\n".join(stderrs))
@@ -82,6 +85,7 @@
         result = __salt__['cmd.run_all'](cmd,
                                          cwd=cwd,
                                          runas=runas,
+                                         output_loglevel='quiet',
                                          env=env,
                                          python_shell=False,
                                          **kwargs)
@@ -90,9 +94,16 @@
         if retcode == 0:
             return result['stdout']
         else:
+            stderr = _remove_sensitive_data(result['stderr'])
             raise CommandExecutionError(
-                'Command {0!r} failed. Stderr: {1!r}'.format(cmd,
-                                                             result['stderr']))
+                'Command {0!r} failed. Stderr: {1!r}'.format(cmd, stderr))
+
+
+def _remove_sensitive_data(sensitive_output):
+    '''
+        Remove HTTP user and password.
+    '''
+    return re.sub('(https?)://.*@', r'\1://<redacted>@', sensitive_output)
 
 
 def _git_getdir(cwd, user=None):
```
