# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4483_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4483_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 60-100 of the vulnerable file.

    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0xFF;
}

int flb_gzip_compress(void *in_data, size_t in_len,
                      void **out_data, size_t *out_len)
{
    int flush;
    int status;
    int footer_start;
    uint8_t *pb;
    size_t out_size;
    void *out_buf;
    z_stream strm;
    mz_ulong crc;

    out_size = in_len + 32;
    out_buf = flb_malloc(out_size);
    if (!out_buf) {
        flb_errno();
        flb_error("[gzip] could not allocate outgoing buffer");
        return -1;
    }

    /* Initialize streaming buffer context */
    memset(&strm, '\0', sizeof(strm));
    strm.zalloc    = Z_NULL;
    strm.zfree     = Z_NULL;
    strm.opaque    = Z_NULL;
    strm.next_in   = in_data;
    strm.avail_in  = in_len;
    strm.total_out = 0;

    /* Deflate mode */
    deflateInit2(&strm, Z_DEFAULT_COMPRESSION,
                 Z_DEFLATED, -Z_DEFAULT_WINDOW_BITS, 9, Z_DEFAULT_STRATEGY);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,8 +77,25 @@
     z_stream strm;
     mz_ulong crc;
 
-    out_size = in_len + 32;
+
+    /*
+     * GZIP relies on an algorithm with worst-case expansion
+     * of 5 bytes per 32KB data. This means we need to create a variable
+     * length output, that depends on the input length.
+     * See RFC 1951 for details.
+     */
+    int max_input_expansion = ((int)(in_len / 32000) + 1) * 5;
+
+    /*
+     * Max compressed size is equal to sum of:
+     *   10 byte header
+     *   8 byte foot
+     *   max input expansion
+     *   size of input
+     */
+    out_size = 10 + 8 + max_input_expansion + in_len;
     out_buf = flb_malloc(out_size);
+
     if (!out_buf) {
         flb_errno();
         flb_error("[gzip] could not allocate outgoing buffer");
```
