# CrossVul Fix Pair: Files or Directories Accessible to External Parties in c
**Pair ID:** 4170_2
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4170_2`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```c
Lines 1-28 of the vulnerable file.

// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_IOV_H
#define _OE_SYSCALL_IOV_H

#include <openenclave/bits/fs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/syscall/fd.h>
#include <openenclave/internal/syscall/sys/stat.h>

OE_EXTERNC_BEGIN

int oe_iov_pack(
    const struct oe_iovec* iov,
    int iovcnt,
    void** buf_out,
    size_t* buf_size_out);

int oe_iov_sync(
    const struct oe_iovec* iov,
    int iovcnt,
    const void* buf_,
    size_t buf_size);

OE_EXTERNC_END

#endif // _OE_SYSCALL_IOV_H
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,8 @@
     const struct oe_iovec* iov,
     int iovcnt,
     void** buf_out,
-    size_t* buf_size_out);
+    size_t* buf_size_out,
+    size_t* data_size_out);
 
 int oe_iov_sync(
     const struct oe_iovec* iov,
```
