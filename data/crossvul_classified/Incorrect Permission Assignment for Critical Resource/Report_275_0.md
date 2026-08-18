# CrossVul Fix Pair: Incorrect Default Permissions in python
**Pair ID:** 275_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `275_0`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```python
Lines 24-64 of the vulnerable file.

import threading
import tempfile
import shutil
import subprocess
import sys

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from .sosnode import SosNode
from distutils.sysconfig import get_python_lib
from getpass import getpass
from six.moves import input
from textwrap import fill
from soscollector import __version__


class SosCollector():
    '''Main sos-collector class'''

    def __init__(self, config):
        self.config = config
        self.threads = []
        self.workers = []
        self.client_list = []
        self.node_list = []
        self.master = False
        self.retrieved = 0
        self.need_local_sudo = False
        if not self.config['list_options']:
            try:
                if not self.config['tmp_dir']:
                    self.create_tmp_dir()
                self._setup_logging()
                self.log_debug('Executing %s' % ' '.join(s for s in sys.argv))
                self._load_clusters()
                self._parse_options()
                self.prep()
            except KeyboardInterrupt:
                self._exit('Exiting on user cancel', 130)
        else:
            self._load_clusters()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,6 +41,7 @@
     '''Main sos-collector class'''
 
     def __init__(self, config):
+        os.umask(0077)
         self.config = config
         self.threads = []
         self.workers = []
```
