# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 402_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `402_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1-31 of the vulnerable file.

/*
 * Description: network buf manager
 *     History: yang@haipo.me, 2016/03/16, create
 */

# include <errno.h>
# include <string.h>
# include "nw_buf.h"

# define NW_BUF_POOL_INIT_SIZE 64
# define NW_CACHE_INIT_SIZE    64

size_t nw_buf_size(nw_buf *buf)
{
    return buf->wpos - buf->rpos;
}

size_t nw_buf_avail(nw_buf *buf)
{
    return buf->size - buf->wpos;
}

size_t nw_buf_write(nw_buf *buf, const void *data, size_t len)
{
    size_t available = buf->size - buf->wpos;
    size_t wlen = len > available ? available : len;
    memcpy(buf->data + buf->wpos, data, wlen);
    buf->wpos += wlen;
    return wlen;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,9 @@
 # include "nw_buf.h"
 
 # define NW_BUF_POOL_INIT_SIZE 64
+# define NW_BUF_POOL_MAX_SIZE  65535
 # define NW_CACHE_INIT_SIZE    64
+# define NW_CACHE_MAX_SIZE     65535
 
 size_t nw_buf_size(nw_buf *buf)
 {
@@ -85,7 +87,7 @@
 {
     if (pool->free < pool->free_total) {
         pool->free_arr[pool->free++] = buf;
-    } else {
+    } else if (pool->free_total < NW_BUF_POOL_MAX_SIZE) {
         uint32_t new_free_total = pool->free_total * 2;
         void *new_arr = realloc(pool->free_arr, new_free_total * sizeof(nw_buf *));
         if (new_arr) {
@@ -95,6 +97,8 @@
         } else {
             free(buf);
         }
+    } else {
+        free(buf);
     }
 }
 
@@ -230,7 +234,7 @@
 {
     if (cache->free < cache->free_total) {
         cache->free_arr[cache->free++] = obj;
-    } else {
+    } else if (cache->free_total < NW_CACHE_MAX_SIZE) {
         uint32_t new_free_total = cache->free_total * 2;
         void *new_arr = realloc(cache->free_arr, new_free_total * sizeof(void *));
         if (new_arr) {
@@ -240,6 +244,8 @@
         } else {
             free(obj);
         }
+    } else {
+        free(obj);
     }
 }
 
```
