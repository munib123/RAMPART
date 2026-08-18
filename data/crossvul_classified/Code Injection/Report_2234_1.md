# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 2234_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2234_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 14-54 of the vulnerable file.

#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import multiprocessing
import signal
import os
import pwd
import Queue
import random
import traceback
import tempfile
import time
import collections
import socket
import base64
import sys
import pipes
import jinja2
import subprocess
import getpass

import ansible.constants as C
import ansible.inventory
from ansible import utils
from ansible.utils import template
from ansible.utils import check_conditional
from ansible.utils import string_functions
from ansible import errors
from ansible import module_common
import poller
import connection
from return_data import ReturnData
from ansible.callbacks import DefaultRunnerCallbacks, vv
from ansible.module_common import ModuleReplacer

module_replacer = ModuleReplacer(strip_comments=False)

HAS_ATFORK=True
try:
    from Crypto.Random import atfork
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,6 +31,7 @@
 import pipes
 import jinja2
 import subprocess
+import shlex
 import getpass
 
 import ansible.constants as C
@@ -394,6 +395,35 @@
 
         return actual_user
 
+    def _count_module_args(self, args):
+        '''
+        Count the number of k=v pairs in the supplied module args. This is
+        basically a specialized version of parse_kv() from utils with a few
+        minor changes.
+        '''
+        options = {}
+        if args is not None:
+            args = args.encode('utf-8')
+            try:
+                lexer = shlex.shlex(args, posix=True)
+                lexer.whitespace_split = True
+                lexer.quotes = '"'
+                lexer.ignore_quotes = "'"
+                vargs = list(lexer)
+            except ValueError, ve:
+                if 'no closing quotation' in str(ve).lower():
+                    raise errors.AnsibleError("error parsing argument string '%s', try quoting the entire line." % args)
+                else:
+                    raise
+            vargs = [x.decode('utf-8') for x in vargs]
+            for x in vargs:
+                if "=" in x:
+                    k, v = x.split("=",1)
+                    if k in options:
+                        raise errors.AnsibleError("a duplicate parameter was found in the argument string (%s)" % k)
+                    options[k] = v
+        return len(options)
+
 
     # *****************************************************
 
@@ -612,6 +642,9 @@
             items_terms = self.module_vars.get('items_lookup_terms', '')
             items_terms = template.template(basedir, items_terms, inject)
             items = utils.plugins.lookup_loader.get(items_plugin, runner=self, basedir=basedir).run(items_terms, inject=inject)
+            # strip out any jinja2 template syntax within
+            # the data returned by the lookup plugin
+            items = utils._clean_data_struct(items, from_remote=True)
             if type(items) != list:
                 raise errors.AnsibleError("lookup plugins have to return a list: %r" % items)
 
@@ -823,7 +856,20 @@
 
         # render module_args and complex_args templates
         try:
+            # When templating module_args, we need to be careful to ensure
+            # that no variables inadvertantly (or maliciously) add params
+            # to the list of args. We do this by counting the number of k=v
+            # pairs before and after templating.
+            num_args_pre = self._count_module_args(module_args)
             module_args = template.template(self.basedir, module_args, inject, fail_on_undefined=self.error_on_undefined_vars)
+            num_args_post = self._count_module_args(module_args)
+            if num_args_pre != num_args_post:
+                raise errors.AnsibleError("A variable inserted a new parameter into the module args. " + \
+                                          "Be sure to quote variables if they contain equal signs (for example: \"{{var}}\").")
+            # And we also make sure nothing added in special flags for things
+            # like the command/shell module (ie. #USE_SHELL)
+            if '#USE_SHELL' in module_args:
+                raise errors.AnsibleError("A variable tried to add #USE_SHELL to the module arguments.")
             complex_args = template.template(self.basedir, complex_args, inject, fail_on_undefined=self.error_on_undefined_vars)
         except jinja2.exceptions.UndefinedError, e:
             raise errors.AnsibleUndefinedVariable("One or more undefined variables: %s" % str(e))
```
