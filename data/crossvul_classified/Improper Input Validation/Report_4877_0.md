# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4877_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4877_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 1-24 of the vulnerable file.

#include "Hub.h"
#include "HTTPSocket.h"
#include <openssl/sha.h>

namespace uWS {

char *Hub::inflate(char *data, size_t &length) {
    dynamicInflationBuffer.clear();

    inflationStream.next_in = (Bytef *) data;
    inflationStream.avail_in = length;

    int err;
    do {
        inflationStream.next_out = (Bytef *) inflationBuffer;
        inflationStream.avail_out = LARGE_BUFFER_SIZE;
        err = ::inflate(&inflationStream, Z_FINISH);
        if (!inflationStream.avail_in) {
            break;
        }
        dynamicInflationBuffer.append(inflationBuffer, LARGE_BUFFER_SIZE - inflationStream.avail_out);
    } while (err == Z_BUF_ERROR);

    inflateReset(&inflationStream);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 #include "Hub.h"
 #include "HTTPSocket.h"
 #include <openssl/sha.h>
+
+static const int INFLATE_LESS_THAN_ROUGHLY = 16777216;
 
 namespace uWS {
 
@@ -18,12 +20,13 @@
         if (!inflationStream.avail_in) {
             break;
         }
+
         dynamicInflationBuffer.append(inflationBuffer, LARGE_BUFFER_SIZE - inflationStream.avail_out);
-    } while (err == Z_BUF_ERROR);
+    } while (err == Z_BUF_ERROR && dynamicInflationBuffer.length() <= INFLATE_LESS_THAN_ROUGHLY);
 
     inflateReset(&inflationStream);
 
-    if (err != Z_BUF_ERROR && err != Z_OK) {
+    if ((err != Z_BUF_ERROR && err != Z_OK) || dynamicInflationBuffer.length() > INFLATE_LESS_THAN_ROUGHLY) {
         length = 0;
         return nullptr;
     }
```
