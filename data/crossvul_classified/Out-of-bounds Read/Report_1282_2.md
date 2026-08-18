# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1282_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1282_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-23 of the vulnerable file.

#include "Python.h"
#include "Python-ast.h"
#include "compile.h"
#include "node.h"
#include "grammar.h"
#include "token.h"
#include "ast.h"
#include "parsetok.h"
#include "errcode.h"

extern grammar _Ta3Parser_Grammar; /* from graminit.c */

// from Python/bltinmodule.c
static const char *
source_as_string(PyObject *cmd, const char *funcname, const char *what, PyCompilerFlags *cf, PyObject **cmd_copy)
{
    const char *str;
    Py_ssize_t size;
    Py_buffer view;

    *cmd_copy = NULL;
    if (PyUnicode_Check(cmd)) {
        cf->cf_flags |= PyCF_IGNORE_COOKIE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 #include "Python.h"
 #include "Python-ast.h"
-#include "compile.h"
+#include "compile-ast3.h"
 #include "node.h"
 #include "grammar.h"
 #include "token.h"
@@ -222,10 +222,13 @@
     PyCompilerFlags localflags;
     perrdetail err;
     int iflags = PARSER_FLAGS(flags);
-
-    node *n = Ta3Parser_ParseStringObject(s, filename,
-                                         &_Ta3Parser_Grammar, start, &err,
-                                         &iflags);
+    node *n;
+
+    if (feature_version >= 7)
+        iflags |= PyPARSE_ASYNC_ALWAYS;
+    n = Ta3Parser_ParseStringObject(s, filename,
+                                    &_Ta3Parser_Grammar, start, &err,
+                                    &iflags);
     if (flags == NULL) {
         localflags.cf_flags = 0;
         flags = &localflags;
```
