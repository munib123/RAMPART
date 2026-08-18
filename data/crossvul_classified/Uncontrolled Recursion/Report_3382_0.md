# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 3382_0
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3382_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 48-68 of the vulnerable file.

#define MAX_PATH 1024
#endif

#define MAX_COMPILER_ERROR_EXTRA_INFO   256
#define MAX_ATOM_LENGTH                 4
#define MAX_LOOP_NESTING                4
#define MAX_ARENA_PAGES                 32
#define MAX_INCLUDE_DEPTH               16
#define MAX_STRING_MATCHES              1000000
#define MAX_FUNCTION_ARGS               128
#define MAX_FAST_RE_STACK               300
#define MAX_OVERLOADED_FUNCTIONS        10
#define MAX_HEX_STRING_TOKENS           10000
#define MAX_MATCH_DATA                  4096

#define LOOP_LOCAL_VARS                 4
#define STRING_CHAINING_THRESHOLD       200
#define LEX_BUF_SIZE                    8192


#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,4 +65,24 @@
 #define LEX_BUF_SIZE                    8192
 
 
+// Maximum allowed split ID, also limiting the number of split instructions
+// allowed in a regular expression. This number can't be increased
+// over 255 without changing RE_SPLIT_ID_TYPE.
+#define RE_MAX_SPLIT_ID                 128
+
+// Maximum stack size for regexp evaluation
+#define RE_MAX_STACK                    1024
+
+// Maximum code size for a compiled regexp
+#define RE_MAX_CODE_SIZE                32768
+
+// Maximum input size scanned by yr_re_exec
+#define RE_SCAN_LIMIT                   4096
+
+// Maximum number of fibers
+#define RE_MAX_FIBERS                   1024
+
+// Maximum number of levels in regexp's AST
+#define RE_MAX_AST_LEVELS               2000
+
 #endif
```
