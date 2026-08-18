# CrossVul Fix Pair: Data Processing Errors in python
**Pair ID:** 1502_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1502_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```python
Lines 1-29 of the vulnerable file.

# -*- coding: utf-8 -*-
'''
Execute chef in server or solo mode
'''

# Import Python libs
import logging
import os

# Import Salt libs
import salt.utils
import salt.utils.decorators as decorators

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load if chef is installed
    '''
    if not salt.utils.which('chef-client'):
        return False
    return True


def _default_logfile(exe_name):

    if salt.utils.is_windows():
        logfile = salt.utils.path_join(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,7 @@
 # Import Python libs
 import logging
 import os
+import tempfile
 
 # Import Salt libs
 import salt.utils
@@ -24,12 +25,16 @@
 
 
 def _default_logfile(exe_name):
-
+    '''
+    Retrieve the logfile name
+    '''
     if salt.utils.is_windows():
-        logfile = salt.utils.path_join(
-            os.environ['TMP'],
-            '{0}.log'.format(exe_name)
-        )
+        logfile_tmp = tempfile.NamedTemporaryFile(dir=os.environ['TMP'],
+                                                  prefix=exe_name,
+                                                  suffix='.log',
+                                                  delete=False)
+        logfile = logfile_tmp.name
+        logfile_tmp.close()
     else:
         logfile = salt.utils.path_join(
             '/var/log',
```
