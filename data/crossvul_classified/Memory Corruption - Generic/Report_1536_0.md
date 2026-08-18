# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1536_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1536_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 23-66 of the vulnerable file.

 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "k5-int.h"

static krb5_error_code
build_principal_va(krb5_context context, krb5_principal princ,
                   unsigned int rlen, const char *realm, va_list ap)
{
    krb5_error_code retval = 0;
    char *r = NULL;
    krb5_data *data = NULL;
    krb5_int32 count = 0;
    krb5_int32 size = 2;  /* initial guess at needed space */
    char *component = NULL;

    data = malloc(size * sizeof(krb5_data));
    if (!data) { retval = ENOMEM; }

    if (!retval) {
        r = strdup(realm);
        if (!r) { retval = ENOMEM; }
    }

    while (!retval && (component = va_arg(ap, char *))) {
        if (count == size) {
            krb5_data *new_data = NULL;

            size *= 2;
            new_data = realloc(data, size * sizeof(krb5_data));
            if (new_data) {
                data = new_data;
            } else {
                retval = ENOMEM;
            }
        }

        if (!retval) {
            data[count].length = strlen(component);
            data[count].data = strdup(component);
            if (!data[count].data) { retval = ENOMEM; }
            count++;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,10 +40,8 @@
     data = malloc(size * sizeof(krb5_data));
     if (!data) { retval = ENOMEM; }
 
-    if (!retval) {
-        r = strdup(realm);
-        if (!r) { retval = ENOMEM; }
-    }
+    if (!retval)
+        r = k5memdup0(realm, rlen, &retval);
 
     while (!retval && (component = va_arg(ap, char *))) {
         if (count == size) {
```
