# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 50_8
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `50_8`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 1-28 of the vulnerable file.

# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
import os
import stat
import sys

#VERSION="2.1dev4"
VERSION="2.23.1"

# Taken from kennethreitz/requests/setup.py
package_directory = os.path.realpath(os.path.dirname(__file__))


def get_file_contents(file_path):
    """Get the context of the file using full path name."""
    content = ""
    try:
        full_path = os.path.join(package_directory, file_path)
        content = open(full_path, 'r').read()
    except:
        print >> sys.stderr, "### could not open file {0!r}".format(file_path)
    return content

def get_file_list(file_path):
    full_path = os.path.join(package_directory, file_path)
    file_list = os.listdir(full_path)
    # now we need to add the path to the files
    return [ file_path + f for f in file_list ]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
 import sys
 
 #VERSION="2.1dev4"
-VERSION="2.23.1"
+VERSION="2.23.2"
 
 # Taken from kennethreitz/requests/setup.py
 package_directory = os.path.realpath(os.path.dirname(__file__))
```
