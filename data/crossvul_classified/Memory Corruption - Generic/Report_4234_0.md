# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4234_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4234_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 414-455 of the vulnerable file.

    newpos = 0;
    diffPtr = diffBlock;
    extraPtr = extraBlock;
    numTuples = PyList_GET_SIZE(controlTuples);
    for (i = 0; i < numTuples; i++) {
        tuple = PyList_GET_ITEM(controlTuples, i);
        if (!PyTuple_Check(tuple)) {
            PyMem_Free(newData);
            PyErr_SetString(PyExc_TypeError, "expecting tuple");
            return NULL;
        }
        if (PyTuple_GET_SIZE(tuple) != 3) {
            PyMem_Free(newData);
            PyErr_SetString(PyExc_TypeError, "expecting tuple of size 3");
            return NULL;
        }
        x = PyLong_AsLong(PyTuple_GET_ITEM(tuple, 0));
        y = PyLong_AsLong(PyTuple_GET_ITEM(tuple, 1));
        z = PyLong_AsLong(PyTuple_GET_ITEM(tuple, 2));
        if (newpos + x > newDataLength ||
                diffPtr + x > diffBlock + diffBlockLength ||
                extraPtr + y > extraBlock + extraBlockLength) {
            PyMem_Free(newData);
            PyErr_SetString(PyExc_ValueError, "corrupt patch (overflow)");
            return NULL;
        }
        memcpy(newData + newpos, diffPtr, x);
        diffPtr += x;
        for (j = 0; j < x; j++)
            if ((oldpos + j >= 0) && (oldpos + j < origDataLength))
                newData[newpos + j] += origData[oldpos + j];
        newpos += x;
        oldpos += x;
        memcpy(newData + newpos, extraPtr, y);
        extraPtr += y;
        newpos += y;
        oldpos += z;
    }

    /* confirm that a valid patch was applied */
    if (newpos != newDataLength ||
            diffPtr != diffBlock + diffBlockLength ||
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -431,8 +431,7 @@
         y = PyLong_AsLong(PyTuple_GET_ITEM(tuple, 1));
         z = PyLong_AsLong(PyTuple_GET_ITEM(tuple, 2));
         if (newpos + x > newDataLength ||
-                diffPtr + x > diffBlock + diffBlockLength ||
-                extraPtr + y > extraBlock + extraBlockLength) {
+                diffPtr + x > diffBlock + diffBlockLength) {
             PyMem_Free(newData);
             PyErr_SetString(PyExc_ValueError, "corrupt patch (overflow)");
             return NULL;
@@ -444,6 +443,12 @@
                 newData[newpos + j] += origData[oldpos + j];
         newpos += x;
         oldpos += x;
+        if (newpos + y > newDataLength ||
+                extraPtr + y > extraBlock + extraBlockLength) {
+            PyMem_Free(newData);
+            PyErr_SetString(PyExc_ValueError, "corrupt patch (overflow)");
+            return NULL;
+        }
         memcpy(newData + newpos, extraPtr, y);
         extraPtr += y;
         newpos += y;
```
