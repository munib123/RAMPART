# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1467_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1467_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 1-40 of the vulnerable file.

# coding: UTF-8
'''Mock D-BUS objects for test suites.'''

# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option) any
# later version.  See http://www.gnu.org/copyleft/lgpl.html for the full text
# of the license.

__author__ = 'Martin Pitt'
__email__ = 'martin.pitt@ubuntu.com'
__copyright__ = '(c) 2012 Canonical Ltd.'
__license__ = 'LGPL 3+'

import copy
import time
import sys
import types
import importlib
from xml.etree import ElementTree

# we do not use this ourselves, but mock methods often want to use this
import os
os  # pyflakes

import dbus
import dbus.service

# global path -> DBusMockObject mapping
objects = {}

MOCK_IFACE = 'org.freedesktop.DBus.Mock'
OBJECT_MANAGER_IFACE = 'org.freedesktop.DBus.ObjectManager'

# stubs to keep code compatible with Python 2 and 3
if sys.version_info[0] >= 3:
    long = int
    unicode = str


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,7 @@
 import sys
 import types
 import importlib
+import imp
 from xml.etree import ElementTree
 
 # we do not use this ourselves, but mock methods often want to use this
@@ -40,14 +41,10 @@
 
 def load_module(name):
     if os.path.exists(name) and os.path.splitext(name)[1] == '.py':
-        sys.path.insert(0, os.path.dirname(os.path.abspath(name)))
-        try:
-            m = os.path.splitext(os.path.basename(name))[0]
-            module = importlib.import_module(m)
-        finally:
-            sys.path.pop(0)
-
-        return module
+        mod = imp.new_module(os.path.splitext(os.path.basename(name))[0])
+        with open(name) as f:
+            exec(f.read(), mod.__dict__, mod.__dict__)
+        return mod
 
     return importlib.import_module('dbusmock.templates.' + name)
 
```
