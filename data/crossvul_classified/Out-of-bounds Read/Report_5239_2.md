# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 5239_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5239_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/**
 * Test that the crafted TGA file doesn't trigger OOB reads.
 */


#include "gd.h"
#include "gdtest.h"


static size_t read_test_file(char **buffer, char *basename);


int main()
{
    gdImagePtr im;
    char *buffer;
    size_t size;

    size = read_test_file(&buffer, "heap_overflow.tga");
    im = gdImageCreateFromTgaPtr(size, (void *) buffer);
    gdTestAssert(im == NULL);
    free(buffer);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /**
- * Test that the crafted TGA file doesn't trigger OOB reads.
+ * Test that crafted TGA files don't trigger OOB reads.
  */
 
 
@@ -7,21 +7,29 @@
 #include "gdtest.h"
 
 
+static void check_file(char *basename);
 static size_t read_test_file(char **buffer, char *basename);
 
 
 int main()
 {
+    check_file("heap_overflow_1.tga");
+    check_file("heap_overflow_2.tga");
+
+    return gdNumFailures();
+}
+
+
+static void check_file(char *basename)
+{
     gdImagePtr im;
     char *buffer;
     size_t size;
 
-    size = read_test_file(&buffer, "heap_overflow.tga");
+    size = read_test_file(&buffer, basename);
     im = gdImageCreateFromTgaPtr(size, (void *) buffer);
     gdTestAssert(im == NULL);
     free(buffer);
-
-    return gdNumFailures();
 }
 
 
```
