# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in python
**Pair ID:** 994_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `994_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```python
Lines 2243-2291 of the vulnerable file.

    """
    for message in _unzip_iter(filename, root, verbose):
        if isinstance(message, ErrorMessage):
            raise Exception(message)


def _unzip_iter(filename, root, verbose=True):
    if verbose:
        sys.stdout.write('Unzipping %s' % os.path.split(filename)[1])
        sys.stdout.flush()

    try:
        zf = zipfile.ZipFile(filename)
    except zipfile.error as e:
        yield ErrorMessage(filename, 'Error with downloaded zip file')
        return
    except Exception as e:
        yield ErrorMessage(filename, e)
        return

    # Get lists of directories & files
    namelist = zf.namelist()
    dirlist = set()
    for x in namelist:
        if x.endswith('/'):
            dirlist.add(x)
        else:
            dirlist.add(x.rsplit('/', 1)[0] + '/')
    filelist = [x for x in namelist if not x.endswith('/')]

    # Create the target directory if it doesn't exist
    if not os.path.exists(root):
        os.mkdir(root)

    # Create the directory structure
    for dirname in sorted(dirlist):
        pieces = dirname[:-1].split('/')
        for i in range(len(pieces)):
            dirpath = os.path.join(root, *pieces[: i + 1])
            if not os.path.exists(dirpath):
                os.mkdir(dirpath)

    # Extract files.
    for i, filename in enumerate(filelist):
        filepath = os.path.join(root, *filename.split('/'))

        try:
            with open(filepath, 'wb') as dstfile, zf.open(filename) as srcfile:
                shutil.copyfileobj(srcfile, dstfile)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2260,42 +2260,8 @@
         yield ErrorMessage(filename, e)
         return
 
-    # Get lists of directories & files
-    namelist = zf.namelist()
-    dirlist = set()
-    for x in namelist:
-        if x.endswith('/'):
-            dirlist.add(x)
-        else:
-            dirlist.add(x.rsplit('/', 1)[0] + '/')
-    filelist = [x for x in namelist if not x.endswith('/')]
-
-    # Create the target directory if it doesn't exist
-    if not os.path.exists(root):
-        os.mkdir(root)
-
-    # Create the directory structure
-    for dirname in sorted(dirlist):
-        pieces = dirname[:-1].split('/')
-        for i in range(len(pieces)):
-            dirpath = os.path.join(root, *pieces[: i + 1])
-            if not os.path.exists(dirpath):
-                os.mkdir(dirpath)
-
-    # Extract files.
-    for i, filename in enumerate(filelist):
-        filepath = os.path.join(root, *filename.split('/'))
-
-        try:
-            with open(filepath, 'wb') as dstfile, zf.open(filename) as srcfile:
-                shutil.copyfileobj(srcfile, dstfile)
-        except Exception as e:
-            yield ErrorMessage(filename, e)
-            return
-
-        if verbose and (i * 10 / len(filelist) > (i - 1) * 10 / len(filelist)):
-            sys.stdout.write('.')
-            sys.stdout.flush()
+    zf.extractall(root)
+
     if verbose:
         print()
 
```
