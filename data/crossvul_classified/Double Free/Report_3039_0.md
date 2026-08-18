# CrossVul Fix Pair: Double Free in cpp
**Pair ID:** 3039_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3039_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```cpp
Lines 1-35 of the vulnerable file.

/*
* Binding for the libssh2 library. Note that there is not a one-to-one correspondance
* between functions in libssh2 and the binding.
* Currently, during the ssh2 handshake, a call to nsock.receive may result in an EOF
* error. This appears to only occur when stressing the ssh server (ie during a brute
* force attempt) or while behind a restrictive firewall/IDS.
* by Devin Bjelland
*/

extern "C" {
#include "libssh2.h"
}
#include "nse_lua.h"

#include "nse_debug.h"
#include "nse_nsock.h"
#include "nse_utility.h"

#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef WIN32
#include <Windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Fcntl.h>
#include <io.h>
#include <assert.h>
#else
#include <netdb.h>
#include <unistd.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,7 +12,6 @@
 }
 #include "nse_lua.h"
 
-#include "nse_debug.h"
 #include "nse_nsock.h"
 #include "nse_utility.h"
 
@@ -295,6 +294,7 @@
 
     if (rc) {
         libssh2_session_free(sshu->session);
+        sshu->session = NULL;
         return luaL_error(L, "Unable to complete libssh2 handshake.");
     }
 
@@ -478,7 +478,7 @@
 }
 
 /*
-* Returns list of supported authenication methods
+* Returns list of supported authentication methods
 */
 static int l_userauth_list (lua_State *L) {
     return userauth_list(L, 0, 0);
```
