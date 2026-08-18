# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2078_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2078_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 11-49 of the vulnerable file.

from . import f2py_testing
from . import diagnose

from .info import __doc__

run_main = f2py2e.run_main
main = f2py2e.main

def compile(source,
            modulename = 'untitled',
            extra_args = '',
            verbose = 1,
            source_fn = None
            ):
    ''' Build extension module from processing source with f2py.
    Read the source of this function for more information.
    '''
    from numpy.distutils.exec_command import exec_command
    import tempfile
    if source_fn is None:
        fname = os.path.join(tempfile.mktemp()+'.f')
    else:
        fname = source_fn

    f = open(fname, 'w')
    f.write(source)
    f.close()

    args = ' -c -m %s %s %s'%(modulename, fname, extra_args)
    c = '%s -c "import numpy.f2py as f2py2e;f2py2e.main()" %s' %(sys.executable, args)
    s, o = exec_command(c)
    if source_fn is None:
        try: os.remove(fname)
        except OSError: pass
    return s

from numpy.testing import Tester
test = Tester().test
bench = Tester().bench
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,20 +28,20 @@
     from numpy.distutils.exec_command import exec_command
     import tempfile
     if source_fn is None:
-        fname = os.path.join(tempfile.mktemp()+'.f')
+        f = tempfile.NamedTemporaryFile(suffix='.f')
     else:
-        fname = source_fn
+        f = open(source_fn, 'w')
 
-    f = open(fname, 'w')
-    f.write(source)
-    f.close()
+    try:
+        f.write(source)
+        f.flush()
 
-    args = ' -c -m %s %s %s'%(modulename, fname, extra_args)
-    c = '%s -c "import numpy.f2py as f2py2e;f2py2e.main()" %s' %(sys.executable, args)
-    s, o = exec_command(c)
-    if source_fn is None:
-        try: os.remove(fname)
-        except OSError: pass
+        args = ' -c -m %s %s %s'%(modulename, f.name, extra_args)
+        c = '%s -c "import numpy.f2py as f2py2e;f2py2e.main()" %s' % \
+                (sys.executable, args)
+        s, o = exec_command(c)
+    finally:
+        f.close()
     return s
 
 from numpy.testing import Tester
```
