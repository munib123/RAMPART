# CrossVul Fix Pair: Data Processing Errors in python
**Pair ID:** 1501_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1501_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```python
Lines 12-52 of the vulnerable file.

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
    '''
    Retrieve the logfile name
    '''
    if salt.utils.is_windows():
        logfile_tmp = tempfile.NamedTemporaryFile(dir=os.environ['TMP'],
                                                  prefix=exe_name,
                                                  suffix='.log',
                                                  delete=False)
        logfile = logfile_tmp.name
        logfile_tmp.close()
    else:
        logfile = salt.utils.path_join(
            '/var/log',
            '{0}.log'.format(exe_name)
        )

    return logfile


@decorators.which('chef-client')
def client(whyrun=False,
           localmode=False,
           logfile=_default_logfile('chef-client'),
           **kwargs):
    '''
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,10 @@
     Retrieve the logfile name
     '''
     if salt.utils.is_windows():
-        logfile_tmp = tempfile.NamedTemporaryFile(dir=os.environ['TMP'],
+        tmp_dir = os.path.join(__opts__['cachedir'], 'tmp')
+        if not os.path.isdir(tmp_dir):
+            os.mkdir(tmp_dir)
+        logfile_tmp = tempfile.NamedTemporaryFile(dir=tmp_dir,
                                                   prefix=exe_name,
                                                   suffix='.log',
                                                   delete=False)
```
