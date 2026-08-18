# CrossVul Fix Pair: Files or Directories Accessible to External Parties in c
**Pair ID:** 4170_3
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4170_3`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```c
Lines 116-156 of the vulnerable file.

/* oe_setsockopt()/oe_getsockopt() options. */
#define OE_SOL_SOCKET 1
#define OE_SO_DEBUG 1
#define OE_SO_REUSEADDR 2
#define OE_SO_TYPE 3
#define OE_SO_ERROR 4
#define OE_SO_DONTROUTE 5
#define OE_SO_BROADCAST 6
#define OE_SO_SNDBUF 7
#define OE_SO_RCVBUF 8
#define OE_SO_SNDBUFFORCE 32
#define OE_SO_RCVBUFFORCE 33
#define OE_SO_KEEPALIVE 9
#define OE_SO_OOBINLINE 10
#define OE_SO_NO_CHECK 11
#define OE_SO_PRIORITY 12
#define OE_SO_LINGER 13
#define OE_SO_BSDCOMPAT 14
#define OE_SO_REUSEPORT 15

/* oe_shutdown() options. */
#define OE_SHUT_RD 0
#define OE_SHUT_WR 1
#define OE_SHUT_RDWR 2

#define OE_MSG_PEEK 0x0002

#define __OE_SOCKADDR_STORAGE oe_sockaddr_storage
#include <openenclave/internal/syscall/sys/bits/sockaddr_storage.h>
#undef __OE_SOCKADDR_STORAGE

#define __OE_IOVEC oe_iovec
#define __OE_MSGHDR oe_msghdr
#include <openenclave/internal/syscall/sys/bits/msghdr.h>
#undef __OE_IOVEC
#undef __OE_MSGHDR

void oe_set_default_socket_devid(uint64_t devid);

uint64_t oe_get_default_socket_devid(void);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,6 +133,9 @@
 #define OE_SO_BSDCOMPAT 14
 #define OE_SO_REUSEPORT 15
 
+/* Socket message flags. */
+#define OE_MSG_CTRUNC 0x0008
+
 /* oe_shutdown() options. */
 #define OE_SHUT_RD 0
 #define OE_SHUT_WR 1
@@ -204,7 +207,7 @@
     void* buf,
     size_t len,
     int flags,
-    const struct oe_sockaddr* src_addr,
+    struct oe_sockaddr* src_addr,
     oe_socklen_t* addrlen);
 
 ssize_t oe_sendmsg(int sockfd, const struct oe_msghdr* buf, int flags);
```
