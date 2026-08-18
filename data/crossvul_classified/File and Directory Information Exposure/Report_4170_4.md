# CrossVul Fix Pair: Files or Directories Accessible to External Parties in c
**Pair ID:** 4170_4
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-552
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4170_4`)

## Vulnerability Information & PoC

## Description
Files or Directories Accessible to External Parties - Web servers, FTP servers, and similar servers may store a set of files underneath a root directory that is accessible to the server's users.

## Vulnerable Code
```c
Lines 188-228 of the vulnerable file.

        case OE_F_GETSIG:
        case OE_F_SETOWN_EX:
        case OE_F_GETOWN_EX:
        case OE_F_GETOWNER_UIDS:
            OE_RAISE_ERRNO(OE_EINVAL);
    }

    if (oe_syscall_fcntl_ocall(
            &ret, file->host_fd, cmd, arg, argsize, argout) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_read(oe_fd_t* file_, void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_read_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

done:
    return ret;
}

static ssize_t _consolefs_write(oe_fd_t* file_, const void* buf, size_t count)
{
    ssize_t ret = -1;
    file_t* file = _cast_file(file_);

    if (!file)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (oe_syscall_write_ocall(&ret, file->host_fd, buf, count) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -205,12 +205,30 @@
     ssize_t ret = -1;
     file_t* file = _cast_file(file_);
 
-    if (!file)
+    /*
+     * According to the POSIX specification, when the count is greater
+     * than SSIZE_MAX, the result is implementation-defined. OE raises an
+     * error in this case.
+     * Refer to
+     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/read.html for
+     * for more detail.
+     */
+    if (!file || count > OE_SSIZE_MAX)
         OE_RAISE_ERRNO(OE_EINVAL);
 
     if (oe_syscall_read_ocall(&ret, file->host_fd, buf, count) != OE_OK)
         OE_RAISE_ERRNO(OE_EINVAL);
 
+    /*
+     * Guard the special case that a host sets an arbitrarily large value.
+     * The returned value should not exceed count.
+     */
+    if (ret > (ssize_t)count)
+    {
+        ret = -1;
+        OE_RAISE_ERRNO(OE_EINVAL);
+    }
+
 done:
     return ret;
 }
@@ -220,11 +238,29 @@
     ssize_t ret = -1;
     file_t* file = _cast_file(file_);
 
-    if (!file)
+    /*
+     * According to the POSIX specification, when the count is greater
+     * than SSIZE_MAX, the result is implementation-defined. OE raises an
+     * error in this case.
+     * Refer to
+     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/write.html for
+     * for more detail.
+     */
+    if (!file || count > OE_SSIZE_MAX)
         OE_RAISE_ERRNO(OE_EINVAL);
 
     if (oe_syscall_write_ocall(&ret, file->host_fd, buf, count) != OE_OK)
         OE_RAISE_ERRNO(OE_EINVAL);
+
+    /*
+     * Guard the special case that a host sets an arbitrarily large value.
+     * The returned value should not exceed count.
+     */
+    if (ret > (ssize_t)count)
+    {
+        ret = -1;
+        OE_RAISE_ERRNO(OE_EINVAL);
+    }
 
 done:
     return ret;
@@ -239,18 +275,40 @@
     file_t* file = _cast_file(desc);
     void* buf = NULL;
     size_t buf_size = 0;
+    size_t data_size = 0;
 
     if (!file || !iov || iovcnt < 0 || iovcnt > OE_IOV_MAX)
         OE_RAISE_ERRNO(OE_EINVAL);
 
     /* Flatten the IO vector into contiguous heap memory. */
-    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
+    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size, &data_size) != 0)
         OE_RAISE_ERRNO(OE_ENOMEM);
+
+    /*
+     * According to the POSIX specification, when the data_size is greater
+     * than SSIZE_MAX, the result is implementation-defined. OE raises an
+     * error in this case.
+     * Refer to
+     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/readv.html for
+     * for more detail.
+     */
+    if (data_size > OE_SSIZE_MAX)
+        OE_RAISE_ERRNO(OE_EINVAL);
 
     /* Call the host. */
     if (oe_syscall_readv_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) !=
         OE_OK)
     {
+        OE_RAISE_ERRNO(OE_EINVAL);
+    }
+
+    /*
+     * Guard the special case that a host sets an arbitrarily large value.
+     * The returned value should not exceed data_size.
+     */
+    if (ret > (ssize_t)data_size)
+    {
+        ret = -1;
         OE_RAISE_ERRNO(OE_EINVAL);
     }
 
@@ -275,18 +333,40 @@
     file_t* file = _cast_file(desc);
     void* buf = NULL;
     size_t buf_size = 0;
+    size_t data_size = 0;
 
     if (!file || (!iov && iovcnt) || iovcnt < 0 || iovcnt > OE_IOV_MAX)
         OE_RAISE_ERRNO(OE_EINVAL);
 
     /* Flatten the IO vector into contiguous heap memory. */
-    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size) != 0)
+    if (oe_iov_pack(iov, iovcnt, &buf, &buf_size, &data_size) != 0)
         OE_RAISE_ERRNO(OE_ENOMEM);
+
+    /*
+     * According to the POSIX specification, when the data_size is greater
+     * than SSIZE_MAX, the result is implementation-defined. OE raises an
+     * error in this case.
+     * Refer to
+     * https://pubs.opengroup.org/onlinepubs/9699919799/functions/writev.html
+     * for more detail.
+     */
+    if (data_size > OE_SSIZE_MAX)
+        OE_RAISE_ERRNO(OE_EINVAL);
 
     /* Call the host. */
     if (oe_syscall_writev_ocall(&ret, file->host_fd, buf, iovcnt, buf_size) !=
         OE_OK)
     {
+        OE_RAISE_ERRNO(OE_EINVAL);
+    }
+
+    /*
+     * Guard the special case that a host sets an arbitrarily large value.
+     * The returned value should not exceed data_size.
+     */
+    if (ret > (ssize_t)data_size)
+    {
+        ret = -1;
         OE_RAISE_ERRNO(OE_EINVAL);
     }
 
```
