# CrossVul Fix Pair: Files or Directories Accessible to External Parties in c
**Pair ID:** 4170_1
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4170_1`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```c
Lines 93-133 of the vulnerable file.


    int (*listen)(oe_fd_t* sock, int backlog);

    ssize_t (*send)(oe_fd_t* sock, const void* buf, size_t len, int flags);

    ssize_t (*recv)(oe_fd_t* sock, void* buf, size_t len, int flags);

    ssize_t (*sendto)(
        oe_fd_t* sock,
        const void* buf,
        size_t len,
        int flags,
        const struct oe_sockaddr* dest_addr,
        oe_socklen_t addrlen);

    ssize_t (*recvfrom)(
        oe_fd_t* sock,
        void* buf,
        size_t len,
        int flags,
        const struct oe_sockaddr* src_addr,
        oe_socklen_t* addrlen);

    ssize_t (*sendmsg)(oe_fd_t* sock, const struct oe_msghdr* msg, int flags);

    ssize_t (*recvmsg)(oe_fd_t* sock, struct oe_msghdr* msg, int flags);

    int (*shutdown)(oe_fd_t* sock, int how);

    int (*getsockopt)(
        oe_fd_t* sock,
        int level,
        int optname,
        void* optval,
        oe_socklen_t* optlen);

    int (*setsockopt)(
        oe_fd_t* sock,
        int level,
        int optname,
        const void* optval,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
         void* buf,
         size_t len,
         int flags,
-        const struct oe_sockaddr* src_addr,
+        struct oe_sockaddr* src_addr,
         oe_socklen_t* addrlen);
 
     ssize_t (*sendmsg)(oe_fd_t* sock, const struct oe_msghdr* msg, int flags);
```
