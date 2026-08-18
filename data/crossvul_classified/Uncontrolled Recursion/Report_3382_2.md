# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 3382_2
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3382_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 34-90 of the vulnerable file.

algorithm as described by Russ Cox in http://swtch.com/~rsc/regexp/regexp2.html.

What the article names a "thread" has been named a "fiber" in this code, in
order to avoid confusion with operating system threads.

*/

#include <assert.h>
#include <string.h>
#include <limits.h>

#include <yara/limits.h>
#include <yara/globals.h>
#include <yara/utils.h>
#include <yara/mem.h>
#include <yara/re.h>
#include <yara/error.h>
#include <yara/threading.h>
#include <yara/re_lexer.h>
#include <yara/hex_lexer.h>

// Maximum allowed split ID, also limiting the number of split instructions
// allowed in a regular expression. This number can't be increased
// over 255 without changing RE_SPLIT_ID_TYPE.
#define RE_MAX_SPLIT_ID     128

// Maximum stack size for regexp evaluation
#define RE_MAX_STACK      1024

// Maximum code size for a compiled regexp
#define RE_MAX_CODE_SIZE  32768

// Maximum input size scanned by yr_re_exec
#define RE_SCAN_LIMIT     4096

// Maximum number of fibers
#define RE_MAX_FIBERS     1024


#define EMIT_BACKWARDS                  0x01
#define EMIT_DONT_SET_FORWARDS_CODE     0x02
#define EMIT_DONT_SET_BACKWARDS_CODE    0x04


typedef struct _RE_REPEAT_ARGS
{
  uint16_t  min;
  uint16_t  max;
  int32_t   offset;

} RE_REPEAT_ARGS;


typedef struct _RE_REPEAT_ANY_ARGS
{
  uint16_t   min;
  uint16_t   max;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,23 +52,6 @@
 #include <yara/re_lexer.h>
 #include <yara/hex_lexer.h>
 
-// Maximum allowed split ID, also limiting the number of split instructions
-// allowed in a regular expression. This number can't be increased
-// over 255 without changing RE_SPLIT_ID_TYPE.
-#define RE_MAX_SPLIT_ID     128
-
-// Maximum stack size for regexp evaluation
-#define RE_MAX_STACK      1024
-
-// Maximum code size for a compiled regexp
-#define RE_MAX_CODE_SIZE  32768
-
-// Maximum input size scanned by yr_re_exec
-#define RE_SCAN_LIMIT     4096
-
-// Maximum number of fibers
-#define RE_MAX_FIBERS     1024
-
 
 #define EMIT_BACKWARDS                  0x01
 #define EMIT_DONT_SET_FORWARDS_CODE     0x02
@@ -268,6 +251,7 @@
     return ERROR_INSUFFICIENT_MEMORY;
 
   (*re_ast)->flags = 0;
+  (*re_ast)->levels = 0;
   (*re_ast)->root_node = NULL;
 
   return ERROR_SUCCESS;
```
