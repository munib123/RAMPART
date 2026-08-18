# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5395_2
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5395_2`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 325-365 of the vulnerable file.

    int ystep;

    if (!PyArg_ParseTuple(args, "O(ii)sOn(sii)", &target, &xsize, &ysize,
                          &codec, &bbox, &offset, &mode, &stride, &ystep))
        return NULL;

    if (!PyImaging_CheckBuffer(target)) {
        PyErr_SetString(PyExc_TypeError, "expected string or buffer");
        return NULL;
    }

    if (stride <= 0) {
        if (!strcmp(mode, "L") || !strcmp(mode, "P"))
            stride = xsize;
        else if (!strncmp(mode, "I;16", 4))
            stride = xsize * 2;
        else
            stride = xsize * 4;
    }

    size = (Py_ssize_t) ysize * stride;

    /* check buffer size */
    if (PyImaging_GetBuffer(target, &view) < 0)
        return NULL;

    if (view.len < 0) {
        PyErr_SetString(PyExc_ValueError, "buffer has negative size");
        return NULL;
    }
    if (offset + size > view.len) {
        PyErr_SetString(PyExc_ValueError, "buffer is not large enough");
        return NULL;
    }

    im = ImagingNewPrologueSubtype(
        mode, xsize, ysize, sizeof(ImagingBufferInstance)
        );
    if (!im)
        return NULL;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -342,7 +342,17 @@
             stride = xsize * 4;
     }
 
+    if (ysize > INT_MAX / stride) {
+        PyErr_SetString(PyExc_MemoryError, "Integer overflow in ysize");
+        return NULL;
+    }
+
     size = (Py_ssize_t) ysize * stride;
+
+    if (offset > SIZE_MAX - size) {
+        PyErr_SetString(PyExc_MemoryError, "Integer overflow in offset");
+        return NULL;
+    }        
 
     /* check buffer size */
     if (PyImaging_GetBuffer(target, &view) < 0)
```
