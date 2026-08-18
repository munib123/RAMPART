# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3348_3
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3348_3`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 34-66 of the vulnerable file.


#include <yara/integers.h>

//
// This struct is used to support strings containing null chars. The length of
// the string is stored along the string data. However the string data is also
// terminated with a null char.
//

#define SIZED_STRING_FLAGS_NO_CASE  1
#define SIZED_STRING_FLAGS_DOT_ALL  2

#pragma pack(push)
#pragma pack(8)


typedef struct _SIZED_STRING
{
  uint32_t length;
  uint32_t flags;
  
  char c_string[1];

} SIZED_STRING;

#pragma pack(pop)


int sized_string_cmp(
  SIZED_STRING* s1,
  SIZED_STRING* s2);

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -51,7 +51,7 @@
 {
   uint32_t length;
   uint32_t flags;
-  
+
   char c_string[1];
 
 } SIZED_STRING;
@@ -60,7 +60,11 @@
 
 
 int sized_string_cmp(
-  SIZED_STRING* s1,
-  SIZED_STRING* s2);
+    SIZED_STRING* s1,
+    SIZED_STRING* s2);
+
+
+SIZED_STRING* sized_string_dup(
+    SIZED_STRING* s);
 
 #endif
```
