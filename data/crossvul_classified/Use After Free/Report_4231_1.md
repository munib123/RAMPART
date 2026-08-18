# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4231_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4231_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1-40 of the vulnerable file.

/*
** $Id: ldo.h $
** Stack and Call structure of Lua
** See Copyright Notice in lua.h
*/

#ifndef ldo_h
#define ldo_h


#include "lobject.h"
#include "lstate.h"
#include "lzio.h"


/*
** Macro to check stack size and grow stack if needed.  Parameters
** 'pre'/'pos' allow the macro to preserve a pointer into the
** stack across reallocations, doing the work only when needed.
** 'condmovestack' is used in heavy tests to force a stack reallocation
** at every check.
*/
#define luaD_checkstackaux(L,n,pre,pos)  \
	if (L->stack_last - L->top <= (n)) \
	  { pre; luaD_growstack(L, n, 1); pos; } \
        else { condmovestack(L,pre,pos); }

/* In general, 'pre'/'pos' are empty (nothing to save) */
#define luaD_checkstack(L,n)	luaD_checkstackaux(L,n,(void)0,(void)0)



#define savestack(L,p)		((char *)(p) - (char *)L->stack)
#define restorestack(L,n)	((StkId)((char *)L->stack + (n)))


/* macro to check stack size, preserving 'p' */
#define checkstackp(L,n,p)  \
  luaD_checkstackaux(L, n, \
    ptrdiff_t t__ = savestack(L, p);  /* save 'p' */ \
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,8 @@
 ** Macro to check stack size and grow stack if needed.  Parameters
 ** 'pre'/'pos' allow the macro to preserve a pointer into the
 ** stack across reallocations, doing the work only when needed.
+** It also allows the running of one GC step when the stack is
+** reallocated.
 ** 'condmovestack' is used in heavy tests to force a stack reallocation
 ** at every check.
 */
@@ -35,7 +37,7 @@
 
 
 /* macro to check stack size, preserving 'p' */
-#define checkstackp(L,n,p)  \
+#define checkstackGCp(L,n,p)  \
   luaD_checkstackaux(L, n, \
     ptrdiff_t t__ = savestack(L, p);  /* save 'p' */ \
     luaC_checkGC(L),  /* stack grow uses memory */ \
@@ -44,7 +46,7 @@
 
 /* macro to check stack size and GC */
 #define checkstackGC(L,fsize)  \
-	luaD_checkstackaux(L, (fsize), (void)0, luaC_checkGC(L))
+	luaD_checkstackaux(L, (fsize), luaC_checkGC(L), (void)0)
 
 
 /* type of protected functions, to be ran by 'runprotected' */
```
