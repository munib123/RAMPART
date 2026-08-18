# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1491_3
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1491_3`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-17 of the vulnerable file.


#ifndef __ctl_defaults_h
#define __ctl_defaults_h
/*listen by default on: */
#ifdef SRNAME
/* this is used when compiling sercmd tool */
#define DEFAULT_CTL_SOCKET  "unixs:/tmp/" SRNAME "_ctl"
#else
/* this is used when compiling sip server */
#define DEFAULT_CTL_SOCKET  "unixs:/tmp/" NAME "_ctl"
#endif
/* port used by default for tcp/udp if no port is explicitely specified */
#define DEFAULT_CTL_PORT 2049

#define PROC_CTL -32

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,10 +4,10 @@
 /*listen by default on: */
 #ifdef SRNAME
 /* this is used when compiling sercmd tool */
-#define DEFAULT_CTL_SOCKET  "unixs:/tmp/" SRNAME "_ctl"
+#define DEFAULT_CTL_SOCKET  "unixs:" RUN_DIR "/" SRNAME "/" SRNAME "_ctl"
 #else
 /* this is used when compiling sip server */
-#define DEFAULT_CTL_SOCKET  "unixs:/tmp/" NAME "_ctl"
+#define DEFAULT_CTL_SOCKET  "unixs:" RUN_DIR "/" NAME "_ctl"
 #endif
 /* port used by default for tcp/udp if no port is explicitely specified */
 #define DEFAULT_CTL_PORT 2049
```
