# CrossVul Fix Pair: Double Free in cpp
**Pair ID:** 1184_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1184_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```cpp
Lines 72-112 of the vulnerable file.

/************************************************************************/

static void* OGRExpatMalloc( size_t size )
{
    if( CanAlloc(size) )
        return malloc(size);

    return nullptr;
}

/************************************************************************/
/*                         OGRExpatRealloc()                            */
/************************************************************************/

// Caller must replace the pointer with the returned pointer.
static void* OGRExpatRealloc( void *ptr, size_t size )
{
    if( CanAlloc(size) )
        return realloc(ptr, size);

    free(ptr);
    return nullptr;
}

/************************************************************************/
/*                            FillWINDOWS1252()                         */
/************************************************************************/

static void FillWINDOWS1252( XML_Encoding *info )
{
    // Map CP1252 bytes to Unicode values.
    for( int i = 0; i < 0x80; ++i )
        info->map[i] = i;

    info->map[0x80] = 0x20AC;
    info->map[0x81] = -1;
    info->map[0x82] = 0x201A;
    info->map[0x83] = 0x0192;
    info->map[0x84] = 0x201E;
    info->map[0x85] = 0x2026;
    info->map[0x86] = 0x2020;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,7 +89,6 @@
     if( CanAlloc(size) )
         return realloc(ptr, size);
 
-    free(ptr);
     return nullptr;
 }
 
```
