# CrossVul Fix Pair: Stack-based Buffer Overflow in c
**Pair ID:** 4502_0
**Vulnerability Class:** Stack Overflow
**CWE:** CWE-121
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4502_0`)

## Vulnerability Information & PoC

## Description
Stack-based Buffer Overflow - A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.

## Vulnerable Code
```c
Lines 41-81 of the vulnerable file.

#define SCP_SESSION_TYPE_XVNC    0x00
#define SCP_SESSION_TYPE_XRDP    0x01
#define SCP_SESSION_TYPE_MANAGE  0x02
#define SCP_SESSION_TYPE_XORG    0x03

/* SCP_GW_AUTHENTICATION can be used when XRDP + sesman act as a gateway
 * XRDP sends this command to let sesman verify if the user is allowed
 * to use the gateway */
#define SCP_GW_AUTHENTICATION    0x04

#define SCP_ADDRESS_TYPE_IPV4 0x00
#define SCP_ADDRESS_TYPE_IPV6 0x01

#define SCP_COMMAND_SET_DEFAULT 0x0000
#define SCP_COMMAND_SET_MANAGE  0x0001
#define SCP_COMMAND_SET_RSR     0x0002

#define SCP_SERVER_MAX_LIST_SIZE 100

#include "libscp_types_mng.h"

struct SCP_CONNECTION
{
  int in_sck;
  struct stream* in_s;
  struct stream* out_s;
};

struct SCP_SESSION
{
  tui8  type;
  tui32 version;
  tui16 height;
  tui16 width;
  tui8  bpp;
  tui8  rsr;
  char  locale[18];
  char* username;
  char* password;
  char* hostname;
  tui8  addr_type;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,10 @@
 #define SCP_SERVER_MAX_LIST_SIZE 100
 
 #include "libscp_types_mng.h"
+
+/* Max server incoming and outgoing message size, used to stop memory
+   exhaustion attempts (CVE-2020-4044) */
+#define SCP_MAX_MESSAGE_SIZE 8192
 
 struct SCP_CONNECTION
 {
```
