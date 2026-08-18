# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 4099_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4099_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 1-27 of the vulnerable file.

#ifndef R2_SOCKET_H
#define R2_SOCKET_H

/* Must be included before windows.h (r_types) */
#if defined(__WINDOWS__)
#include <ws2tcpip.h>
#endif

#include "r_types.h"
#include "r_bind.h"
#include "r_list.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_socket);

#if __UNIX__
#include <netinet/in.h>
#include <sys/un.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,10 +1,5 @@
 #ifndef R2_SOCKET_H
 #define R2_SOCKET_H
-
-/* Must be included before windows.h (r_types) */
-#if defined(__WINDOWS__)
-#include <ws2tcpip.h>
-#endif
 
 #include "r_types.h"
 #include "r_bind.h"
```
