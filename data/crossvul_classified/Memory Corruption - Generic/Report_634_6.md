# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 634_6
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `634_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.

 * Released under LGPL 28.JAN.99
 *
 * Contributions from...
 * -----------------------------------------------
 * Peter Harvey		- pharvey@codebydesign.com
 **************************************************/
#include <config.h>
#include <odbcinstext.h>

/*
 * Take a wide string consisting of null terminated sections, and copy to a ASCII version
 */

char* _multi_string_alloc_and_copy( LPCWSTR in )
{
    char *chr;
    int len = 0;

    if ( !in )
    {
        return in;
    }

    while ( in[ len ] != 0 || in[ len + 1 ] != 0 )
    {
        len ++;
    }

    chr = malloc( len + 2 );

    len = 0;
    while ( in[ len ] != 0 || in[ len + 1 ] != 0 )
    {
        chr[ len ] = 0xFF & in[ len ];
        len ++;
    }
    chr[ len ++ ] = '\0';
    chr[ len ++ ] = '\0';

    return chr;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
 
     if ( !in )
     {
-        return in;
+        return NULL;
     }
 
     while ( in[ len ] != 0 || in[ len + 1 ] != 0 )
@@ -55,7 +55,7 @@
 
     if ( !in )
     {
-        return in;
+        return NULL;
     }
 
     while ( in[ len ] != 0 )
@@ -83,7 +83,7 @@
 
     if ( !in )
     {
-        return in;
+        return NULL;
     }
     
     while ( in[ len ] != 0 || in[ len + 1 ] != 0 )
@@ -112,7 +112,7 @@
 
     if ( !in )
     {
-        return in;
+        return NULL;
     }
 
     while ( in[ len ] != 0 )
```
