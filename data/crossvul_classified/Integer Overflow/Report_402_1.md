# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 402_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `402_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 27-67 of the vulnerable file.

    if (crc32 != generate_crc32c(data, pkg_size))
        return -3;
    pkg->crc32 = crc32;

    pkg->magic     = le32toh(pkg->magic);
    pkg->command   = le32toh(pkg->command);
    pkg->pkg_type  = le16toh(pkg->pkg_type);
    pkg->result    = le32toh(pkg->result);
    pkg->sequence  = le32toh(pkg->sequence);
    pkg->req_id    = le64toh(pkg->req_id);
    pkg->body_size = le32toh(pkg->body_size);
    pkg->ext_size  = le16toh(pkg->ext_size);

    return pkg_size;
}

int rpc_pack(rpc_pkg *pkg, void **data, uint32_t *size)
{
    static void *send_buf;
    static size_t send_buf_size;
    uint32_t pkg_size = RPC_PKG_HEAD_SIZE + pkg->ext_size + pkg->body_size;
    if (send_buf_size < pkg_size) {
        if (send_buf)
            free(send_buf);
        send_buf_size = pkg_size * 2;
        send_buf = malloc(send_buf_size);
        assert(send_buf != NULL);
    }

    memcpy(send_buf, pkg, RPC_PKG_HEAD_SIZE);
    if (pkg->ext_size)
        memcpy(send_buf + RPC_PKG_HEAD_SIZE, pkg->ext, pkg->ext_size);
    if (pkg->body_size)
        memcpy(send_buf + RPC_PKG_HEAD_SIZE + pkg->ext_size, pkg->body, pkg->body_size);

    pkg = send_buf;
    pkg->magic     = htole32(RPC_PKG_MAGIC);
    pkg->command   = htole32(pkg->command);
    pkg->pkg_type  = htole16(pkg->pkg_type);
    pkg->result    = htole32(pkg->result);
    pkg->sequence  = htole32(pkg->sequence);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,13 +44,19 @@
 {
     static void *send_buf;
     static size_t send_buf_size;
-    uint32_t pkg_size = RPC_PKG_HEAD_SIZE + pkg->ext_size + pkg->body_size;
+    uint32_t pkg_size;
+    if (pkg->body_size > RPC_PKG_MAX_BODY_SIZE) {
+        return -1;
+    }
+    pkg_size = RPC_PKG_HEAD_SIZE + pkg->ext_size + pkg->body_size;
     if (send_buf_size < pkg_size) {
         if (send_buf)
             free(send_buf);
         send_buf_size = pkg_size * 2;
         send_buf = malloc(send_buf_size);
-        assert(send_buf != NULL);
+        if (send_buf == NULL) {
+            return -1;
+        }
     }
 
     memcpy(send_buf, pkg, RPC_PKG_HEAD_SIZE);
```
