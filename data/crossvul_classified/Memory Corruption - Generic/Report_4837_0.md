# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4837_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4837_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2721-2761 of the vulnerable file.

    HTTPContext *c1;
    int len, loop_run = 0;

    while (c->chunked_encoding && !c->chunk_size &&
           c->buffer_end > c->buffer_ptr) {
        /* read chunk header, if present */
        len = recv(c->fd, c->buffer_ptr, 1, 0);

        if (len < 0) {
            if (ff_neterrno() != AVERROR(EAGAIN) &&
                ff_neterrno() != AVERROR(EINTR))
                /* error : close connection */
                goto fail;
            return 0;
        } else if (len == 0) {
            /* end of connection : close it */
            goto fail;
        } else if (c->buffer_ptr - c->buffer >= 2 &&
                   !memcmp(c->buffer_ptr - 1, "\r\n", 2)) {
            c->chunk_size = strtol(c->buffer, 0, 16);
            if (c->chunk_size == 0) // end of stream
                goto fail;
            c->buffer_ptr = c->buffer;
            break;
        } else if (++loop_run > 10)
            /* no chunk header, abort */
            goto fail;
        else
            c->buffer_ptr++;
    }

    if (c->buffer_end > c->buffer_ptr) {
        len = recv(c->fd, c->buffer_ptr,
                   FFMIN(c->chunk_size, c->buffer_end - c->buffer_ptr), 0);
        if (len < 0) {
            if (ff_neterrno() != AVERROR(EAGAIN) &&
                ff_neterrno() != AVERROR(EINTR))
                /* error : close connection */
                goto fail;
        } else if (len == 0)
            /* end of connection : close it */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2738,8 +2738,10 @@
         } else if (c->buffer_ptr - c->buffer >= 2 &&
                    !memcmp(c->buffer_ptr - 1, "\r\n", 2)) {
             c->chunk_size = strtol(c->buffer, 0, 16);
-            if (c->chunk_size == 0) // end of stream
+            if (c->chunk_size <= 0) { // end of stream or invalid chunk size
+                c->chunk_size = 0;
                 goto fail;
+            }
             c->buffer_ptr = c->buffer;
             break;
         } else if (++loop_run > 10)
@@ -2761,6 +2763,7 @@
             /* end of connection : close it */
             goto fail;
         else {
+            av_assert0(len <= c->chunk_size);
             c->chunk_size -= len;
             c->buffer_ptr += len;
             c->data_count += len;
```
