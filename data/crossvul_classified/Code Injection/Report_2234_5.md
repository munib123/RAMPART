# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 2234_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2234_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 33-73 of the vulnerable file.

import ast
import time
import StringIO
import stat
import termios
import tty
import pipes
import random
import difflib
import warnings
import traceback
import getpass
import sys
import json

from vault import VaultLib

VERBOSITY=0

MAX_FILE_SIZE_FOR_DIFF=1*1024*1024

try:
    import json
except ImportError:
    import simplejson as json

try:
    from hashlib import md5 as _md5
except ImportError:
    from md5 import md5 as _md5

PASSLIB_AVAILABLE = False
try:
    import passlib.hash
    PASSLIB_AVAILABLE = True
except:
    pass

try:
    import builtin
except ImportError:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,6 +51,10 @@
 
 MAX_FILE_SIZE_FOR_DIFF=1*1024*1024
 
+# caching the compilation of the regex used
+# to check for lookup calls within data
+LOOKUP_REGEX=re.compile(r'lookup\s*\(')
+
 try:
     import json
 except ImportError:
@@ -313,38 +317,44 @@
 
     return json.loads(data)
 
-def _clean_data(orig_data):
+def _clean_data(orig_data, from_remote=False, from_inventory=False):
     ''' remove template tags from a string '''
     data = orig_data
     if isinstance(orig_data, basestring):
-        for pattern,replacement in (('{{','{#'), ('}}','#}'), ('{%','{#'), ('%}','#}')):
+        sub_list = [('{%','{#'), ('%}','#}')]
+        if from_remote or (from_inventory and '{{' in data and LOOKUP_REGEX.search(data)):
+            # if from a remote, we completely disable any jinja2 blocks
+            sub_list.extend([('{{','{#'), ('}}','#}')])
+        for pattern,replacement in sub_list:
             data = data.replace(pattern, replacement)
     return data
 
-def _clean_data_struct(orig_data):
+def _clean_data_struct(orig_data, from_remote=False, from_inventory=False):
     '''
     walk a complex data structure, and use _clean_data() to
     remove any template tags that may exist
     '''
+    if not from_remote and not from_inventory:
+        raise errors.AnsibleErrors("when cleaning data, you must specify either from_remote or from_inventory")
     if isinstance(orig_data, dict):
         data = orig_data.copy()
         for key in data:
-            new_key = _clean_data_struct(key)
-            new_val = _clean_data_struct(data[key])
+            new_key = _clean_data_struct(key, from_remote, from_inventory)
+            new_val = _clean_data_struct(data[key], from_remote, from_inventory)
             if key != new_key:
                 del data[key]
             data[new_key] = new_val
     elif isinstance(orig_data, list):
         data = orig_data[:]
         for i in range(0, len(data)):
-            data[i] = _clean_data_struct(data[i])
+            data[i] = _clean_data_struct(data[i], from_remote, from_inventory)
     elif isinstance(orig_data, basestring):
-        data = _clean_data(orig_data)
+        data = _clean_data(orig_data, from_remote, from_inventory)
     else:
         data = orig_data
     return data
 
-def parse_json(raw_data, from_remote=False):
+def parse_json(raw_data, from_remote=False, from_inventory=False):
     ''' this version for module return data only '''
 
     orig_data = raw_data
@@ -379,9 +389,30 @@
             return { "failed" : True, "parsed" : False, "msg" : orig_data }
 
     if from_remote:
-        results = _clean_data_struct(results)
+        results = _clean_data_struct(results, from_remote, from_inventory)
 
     return results
+
+def merge_module_args(current_args, new_args):
+    '''
+    merges either a dictionary or string of k=v pairs with another string of k=v pairs,
+    and returns a new k=v string without duplicates.
+    '''
+    if not isinstance(current_args, basestring):
+        raise errors.AnsibleError("expected current_args to be a basestring")
+    # we use parse_kv to split up the current args into a dictionary
+    final_args = parse_kv(current_args)
+    if isinstance(new_args, dict):
+        final_args.update(new_args)
+    elif isinstance(new_args, basestring):
+        new_args_kv = parse_kv(new_args)
+        final_args.update(new_args_kv)
+    # then we re-assemble into a string
+    module_args = ""
+    for (k,v) in final_args.iteritems():
+        if isinstance(v, basestring):
+            module_args = "%s=%s %s" % (k, pipes.quote(v), module_args)
+    return module_args.strip()
 
 def smush_braces(data):
     ''' smush Jinaj2 braces so unresolved templates like {{ foo }} don't get parsed weird by key=value code '''
@@ -615,7 +646,7 @@
         for x in vargs:
             if "=" in x:
                 k, v = x.split("=",1)
-                options[k]=v
+                options[k] = v
     return options
 
 def merge_hash(a, b):
@@ -1062,11 +1093,14 @@
 
 def safe_eval(expr, locals={}, include_exceptions=False):
     '''
-    this is intended for allowing things like:
+    This is intended for allowing things like:
     with_items: a_list_variable
-    where Jinja2 would return a string
-    but we do not want to allow it to call functions (outside of Jinja2, where
-    the env is constrained)
+
+    Where Jinja2 would return a string but we do not want to allow it to
+    call functions (outside of Jinja2, where the env is constrained). If
+    the input data to this function came from an untrusted (remote) source,
+    it should first be run through _clean_data_struct() to ensure the data
+    is further sanitized prior to evaluation.
 
     Based on:
     http://stackoverflow.com/questions/12523516/using-ast-and-whitelists-to-make-pythons-eval-safe
```
