# CrossVul Fix Pair: Data Processing Errors in python
**Pair ID:** 1500_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1500_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```python
Lines 1-31 of the vulnerable file.

# -*- coding: utf-8 -*-
'''
Wrapper around Server Density API
=================================

.. versionadded:: 2014.7.0
'''
import requests
import json
import logging

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def get_sd_auth(val, sd_auth_pillar_name='serverdensity'):
    '''
    Returns requested Server Density authentication value from pillar.

    CLI Example:

    .. code-block:: bash

        salt '*' serverdensity_device.get_sd_auth <val>
    '''
    sd_pillar = __pillar__.get(sd_auth_pillar_name)
    log.debug('Server Density Pillar: {0}'.format(sd_pillar))
    if not sd_pillar:
        log.error('Cloud not load {0} pillar'.format(sd_auth_pillar_name))
        raise CommandExecutionError(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,8 @@
 import requests
 import json
 import logging
+import os
+import tempfile
 
 from salt.exceptions import CommandExecutionError
 
@@ -216,17 +218,24 @@
 
         salt '*' serverdensity_device.install_agent c2bbdd6689ff46282bdaa07555641498
     '''
-    work_dir = '/tmp/'
+    work_dir = os.path.join(__opts__['cachedir'], 'tmp')
+    if not os.path.isdir(work_dir):
+        os.mkdir(work_dir)
+    install_file = tempfile.NamedTemporaryFile(dir=work_dir,
+                                                   suffix='.sh',
+                                                   delete=False)
+    install_filename = install_file.name
+    install_file.close()
     account_url = get_sd_auth('account_url')
 
     __salt__['cmd.run'](
-        cmd='curl https://www.serverdensity.com/downloads/agent-install.sh -o install.sh',
+        cmd='curl https://www.serverdensity.com/downloads/agent-install.sh -o {0}'.format(install_filename),
         cwd=work_dir
     )
-    __salt__['cmd.run'](cmd='chmod +x install.sh', cwd=work_dir)
+    __salt__['cmd.run'](cmd='chmod +x {0}'.format(install_filename), cwd=work_dir)
 
     return __salt__['cmd.run'](
-        cmd='./install.sh -a {account_url} -k {agent_key}'.format(
-            account_url=account_url, agent_key=agent_key),
+        cmd='./{filename} -a {account_url} -k {agent_key}'.format(
+            filename=install_filename, account_url=account_url, agent_key=agent_key),
         cwd=work_dir
     )
```
