# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3171_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3171_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 18-54 of the vulnerable file.

 * program's maintainer or write to: The Free Software Foundation,
 * Inc.; 59 Temple Place, Suite 330; Boston, MA 02111-1307, USA.
 *
 */
#ifndef ALLOC_H
#define ALLOC_H

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include "common.h"

#if !STDC_HEADERS
extern void free (void*);
#endif /* STDC_HEADERS */

extern void set_alloc_limit (size_t size);
extern size_t get_alloc_limit();
extern void alloc_limit_assert (char *fn_name, size_t size);
extern void* checked_xmalloc (size_t size);
extern void* xmalloc (size_t size);
extern void* checked_xcalloc (size_t num, size_t size);
extern void* xcalloc (size_t num, size_t size);

#define XMALLOC(_type,_num)			                \
        ((_type*)xmalloc((_num)*sizeof(_type)))
#define XCALLOC(_type,_num) 				        \
        ((_type*)xcalloc((_num), sizeof (_type)))
#define CHECKED_XMALLOC(_type,_num) 			        \
        ((_type*)checked_xmalloc((_num)*sizeof(_type)))
#define CHECKED_XCALLOC(_type,_num) 			        \
        ((_type*)checked_xcalloc((_num),sizeof(_type)))
#define XFREE(_ptr)						\
	do { if (_ptr) { free (_ptr); _ptr = 0; } } while (0)

#endif /* ALLOC_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,20 +35,20 @@
 extern void set_alloc_limit (size_t size);
 extern size_t get_alloc_limit();
 extern void alloc_limit_assert (char *fn_name, size_t size);
-extern void* checked_xmalloc (size_t size);
-extern void* xmalloc (size_t size);
+extern void* checked_xmalloc (size_t num, size_t size);
+extern void* xmalloc (size_t num, size_t size);
 extern void* checked_xcalloc (size_t num, size_t size);
 extern void* xcalloc (size_t num, size_t size);
 
 #define XMALLOC(_type,_num)			                \
-        ((_type*)xmalloc((_num)*sizeof(_type)))
+        ((_type*)xmalloc((_num), sizeof(_type)))
 #define XCALLOC(_type,_num) 				        \
         ((_type*)xcalloc((_num), sizeof (_type)))
 #define CHECKED_XMALLOC(_type,_num) 			        \
-        ((_type*)checked_xmalloc((_num)*sizeof(_type)))
+        ((_type*)checked_xmalloc((_num),sizeof(_type)))
 #define CHECKED_XCALLOC(_type,_num) 			        \
         ((_type*)checked_xcalloc((_num),sizeof(_type)))
 #define XFREE(_ptr)						\
-	do { if (_ptr) { free (_ptr); _ptr = 0; } } while (0)
+        do { if (_ptr) { free (_ptr); _ptr = 0; } } while (0)
 
 #endif /* ALLOC_H */
```
