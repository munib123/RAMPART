# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1281_6
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1281_6`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 5-45 of the vulnerable file.

#include "code.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface */
struct _node; /* Declare the existence of this type */
PyAPI_FUNC(PyCodeObject *) PyNode_Compile(struct _node *, const char *);
/* XXX (ncoghlan): Unprefixed type name in a public API! */

#define PyCF_MASK (CO_FUTURE_DIVISION | CO_FUTURE_ABSOLUTE_IMPORT | \
                   CO_FUTURE_WITH_STATEMENT | CO_FUTURE_PRINT_FUNCTION | \
                   CO_FUTURE_UNICODE_LITERALS | CO_FUTURE_BARRY_AS_BDFL | \
                   CO_FUTURE_GENERATOR_STOP | CO_FUTURE_ANNOTATIONS)
#define PyCF_MASK_OBSOLETE (CO_NESTED)
#define PyCF_SOURCE_IS_UTF8  0x0100
#define PyCF_DONT_IMPLY_DEDENT 0x0200
#define PyCF_ONLY_AST 0x0400
#define PyCF_IGNORE_COOKIE 0x0800

#ifndef Py_LIMITED_API
typedef struct {
    int cf_flags;  /* bitmask of CO_xxx flags relevant to future */
} PyCompilerFlags;
#endif

/* Future feature support */

typedef struct {
    int ff_features;      /* flags set by future statements */
    int ff_lineno;        /* line number of last future statement */
} PyFutureFeatures;

#define FUTURE_NESTED_SCOPES "nested_scopes"
#define FUTURE_GENERATORS "generators"
#define FUTURE_DIVISION "division"
#define FUTURE_ABSOLUTE_IMPORT "absolute_import"
#define FUTURE_WITH_STATEMENT "with_statement"
#define FUTURE_PRINT_FUNCTION "print_function"
#define FUTURE_UNICODE_LITERALS "unicode_literals"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
 #define PyCF_DONT_IMPLY_DEDENT 0x0200
 #define PyCF_ONLY_AST 0x0400
 #define PyCF_IGNORE_COOKIE 0x0800
+#define PyCF_TYPE_COMMENTS 0x1000
 
 #ifndef Py_LIMITED_API
 typedef struct {
@@ -85,10 +86,10 @@
 
 #endif /* !Py_LIMITED_API */
 
-/* These definitions must match corresponding definitions in graminit.h.
-   There's code in compile.c that checks that they are the same. */
+/* These definitions must match corresponding definitions in graminit.h. */
 #define Py_single_input 256
 #define Py_file_input 257
 #define Py_eval_input 258
+#define Py_func_type_input 345
 
 #endif /* !Py_COMPILE_H */
```
