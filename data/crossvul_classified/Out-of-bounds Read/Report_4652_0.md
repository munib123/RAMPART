# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4652_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4652_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

#include "udp.h"

/*
 * SOMEIP Header (R19-11)
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |               Message ID (Service ID/Method ID)               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           Length                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |               Request ID (Client ID/Session ID)               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Protocol Ver  | Interface Ver | Message Type  |  Return Code  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                            Payload                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct tok message_type_values[] = {
    { 0x00, "REQUEST" },
    { 0x01, "REQUEST_NO_RETURN" },
    { 0x02, "NOTIFICATION" },
    { 0x80, "RESPONSE" },
    { 0x81, "ERROR" },
    { 0x20, "TP_REQUEST" },
    { 0x21, "TP_REQUEST_NO_RETURN" },
    { 0x22, "TP_NOTIFICATION" },
    { 0xa0, "TP_RESPONSE" },
    { 0xa1, "TP_ERROR" },
    { 0, NULL }
};

struct tok return_code_values[] = {
    { 0x00, "E_OK" },
    { 0x01, "E_NOT_OK" },
    { 0x02, "E_UNKNOWN_SERVICE" },
    { 0x03, "E_UNKNOWN_METHOD" },
    { 0x04, "E_NOT_READY" },
    { 0x05, "E_NOT_REACHABLE" },
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,7 @@
  *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
 
-struct tok message_type_values[] = {
+static const struct tok message_type_values[] = {
     { 0x00, "REQUEST" },
     { 0x01, "REQUEST_NO_RETURN" },
     { 0x02, "NOTIFICATION" },
@@ -56,7 +56,7 @@
     { 0, NULL }
 };
 
-struct tok return_code_values[] = {
+static const struct tok return_code_values[] = {
     { 0x00, "E_OK" },
     { 0x01, "E_NOT_OK" },
     { 0x02, "E_UNKNOWN_SERVICE" },
@@ -73,6 +73,7 @@
     { 0x0d, "E_E2E" },
     { 0x0e, "E_E2E_NOT_AVAILABLE" },
     { 0x0f, "E_E2E_NO_NEW_DATA" },
+    { 0, NULL }
 };
 
 void
```
