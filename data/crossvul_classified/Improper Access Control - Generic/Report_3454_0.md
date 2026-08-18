# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3454_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3454_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 20-60 of the vulnerable file.

#define _CIFS_GLOB_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/slow-work.h>
#include "cifs_fs_sb.h"
#include "cifsacl.h"
/*
 * The sizes of various internal tables and strings
 */
#define MAX_UID_INFO 16
#define MAX_SES_INFO 2
#define MAX_TCON_INFO 4

#define MAX_TREE_SIZE (2 + MAX_SERVER_SIZE + 1 + MAX_SHARE_SIZE + 1)
#define MAX_SERVER_SIZE 15
#define MAX_SHARE_SIZE  64	/* used to be 20, this should still be enough */
#define MAX_USERNAME_SIZE 32	/* 32 is to allow for 15 char names + null
				   termination then *2 for unicode versions */
#define MAX_PASSWORD_SIZE 16

#define CIFS_MIN_RCV_POOL 4

/*
 * MAX_REQ is the maximum number of requests that WE will send
 * on one socket concurrently. It also matches the most common
 * value of max multiplex returned by servers.  We may
 * eventually want to use the negotiated value (in case
 * future servers can handle more) when we are more confident that
 * we will not have problems oveloading the socket with pending
 * write data.
 */
#define CIFS_MAX_REQ 50

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

/* currently length of NIP6_FMT */
#define SERVER_NAME_LENGTH 40
#define SERVER_NAME_LEN_WITH_NULL     (SERVER_NAME_LENGTH + 1)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,7 +37,7 @@
 #define MAX_SHARE_SIZE  64	/* used to be 20, this should still be enough */
 #define MAX_USERNAME_SIZE 32	/* 32 is to allow for 15 char names + null
 				   termination then *2 for unicode versions */
-#define MAX_PASSWORD_SIZE 16
+#define MAX_PASSWORD_SIZE 512  /* max for windows seems to be 256 wide chars */
 
 #define CIFS_MIN_RCV_POOL 4
 
```
