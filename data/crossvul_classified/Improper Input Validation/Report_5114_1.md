# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5114_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5114_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 29-54 of the vulnerable file.

#include <glib.h>
#include "wtap.h"

/* Magic text to check for NetScreen snoop output */
#define NETSCREEN_HDR_MAGIC_STR1	"(i) len="
#define NETSCREEN_HDR_MAGIC_STR2	"(o) len="

/* Magic text for start of packet */
#define NETSCREEN_REC_MAGIC_STR1	NETSCREEN_HDR_MAGIC_STR1
#define NETSCREEN_REC_MAGIC_STR2	NETSCREEN_HDR_MAGIC_STR2

#define NETSCREEN_LINE_LENGTH		128
#define NETSCREEN_HEADER_LINES_TO_CHECK	32
#define NETSCREEN_MAX_INFOLINES		8
#define NETSCREEN_SPACES_ON_INFO_LINE	14
#define NETSCREEN_MAX_INT_NAME_LENGTH	16

#define NETSCREEN_INGRESS		FALSE
#define NETSCREEN_EGRESS		TRUE


#define NETSCREEN_MAX_PACKET_LEN	65536

wtap_open_return_val netscreen_open(wtap *wth, int *err, gchar **err_info);

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,9 +46,6 @@
 #define NETSCREEN_INGRESS		FALSE
 #define NETSCREEN_EGRESS		TRUE
 
-
-#define NETSCREEN_MAX_PACKET_LEN	65536
-
 wtap_open_return_val netscreen_open(wtap *wth, int *err, gchar **err_info);
 
 #endif
```
