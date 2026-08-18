# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 2815_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2815_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 463-511 of the vulnerable file.

def clean_path(root, path, subdir=False):
    '''
    Accepts the root the path needs to be under and verifies that the path is
    under said root. Pass in subdir=True if the path can result in a
    subdirectory of the root instead of having to reside directly in the root
    '''
    if not os.path.isabs(root):
        return ''
    if not os.path.isabs(path):
        path = os.path.join(root, path)
    path = os.path.normpath(path)
    if subdir:
        if path.startswith(root):
            return path
    else:
        if os.path.dirname(path) == os.path.normpath(root):
            return path
    return ''


def clean_id(id_):
    '''
    Returns if the passed id is clean.
    '''
    if re.search(r'\.\.\{sep}'.format(sep=os.sep), id_):
        return False
    return True


def valid_id(opts, id_):
    '''
    Returns if the passed id is valid
    '''
    try:
        return bool(clean_path(opts['pki_dir'], id_)) and clean_id(id_)
    except (AttributeError, KeyError, TypeError) as e:
        return False


def safe_py_code(code):
    '''
    Check a string to see if it has any potentially unsafe routines which
    could be executed via python, this routine is used to improve the
    safety of modules suct as virtualenv
    '''
    bads = (
            'import',
            ';',
            'subprocess',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -480,22 +480,15 @@
     return ''
 
 
-def clean_id(id_):
-    '''
-    Returns if the passed id is clean.
-    '''
-    if re.search(r'\.\.\{sep}'.format(sep=os.sep), id_):
-        return False
-    return True
-
-
 def valid_id(opts, id_):
     '''
     Returns if the passed id is valid
     '''
     try:
-        return bool(clean_path(opts['pki_dir'], id_)) and clean_id(id_)
-    except (AttributeError, KeyError, TypeError) as e:
+        if any(x in id_ for x in ('/', '\\', '\0')):
+            return False
+        return bool(clean_path(opts['pki_dir'], id_))
+    except (AttributeError, KeyError, TypeError):
         return False
 
 
```
