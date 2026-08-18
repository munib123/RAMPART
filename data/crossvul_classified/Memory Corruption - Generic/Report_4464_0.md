# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4464_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4464_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 689-729 of the vulnerable file.

    memcpy(&value2, ref, 8);
#else
    value2 = *(int64_t*)ip;
#endif
    if (value != value2) {
      // Values differ.  We don't have a run.
      return false;
    }
    else {
      ip += 8;
    }
  }
  /* Look into the remainder */
  while ((ip < ip_bound) && (*ip == x)) ip++;
  return ip == ip_bound ? true : false;
}


/* Shuffle & compress a single block */
static int blosc_c(struct thread_context* thread_context, int32_t bsize,
                   int32_t leftoverblock, int32_t ntbytes, int32_t maxbytes,
                   const uint8_t* src, const int32_t offset, uint8_t* dest,
                   uint8_t* tmp, uint8_t* tmp2) {
  blosc2_context* context = thread_context->parent_context;
  int dont_split = (context->header_flags & 0x10) >> 4;
  int dict_training = context->use_dict && context->dict_cdict == NULL;
  int32_t j, neblock, nstreams;
  int32_t cbytes;                   /* number of compressed bytes in split */
  int32_t ctbytes = 0;              /* number of compressed bytes in block */
  int64_t maxout;
  int32_t typesize = context->typesize;
  const char* compname;
  int accel;
  const uint8_t* _src;
  uint8_t *_tmp = tmp, *_tmp2 = tmp2;
  uint8_t *_tmp3 = thread_context->tmp4;
  int last_filter_index = last_filter(context->filters, 'c');
  bool memcpyed = context->header_flags & (uint8_t)BLOSC_MEMCPYED;

  if (last_filter_index >= 0 || context->prefilter != NULL) {
    /* Apply the filter pipeline just for the prefilter */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -706,7 +706,7 @@
 
 /* Shuffle & compress a single block */
 static int blosc_c(struct thread_context* thread_context, int32_t bsize,
-                   int32_t leftoverblock, int32_t ntbytes, int32_t maxbytes,
+                   int32_t leftoverblock, int32_t ntbytes, int32_t destsize,
                    const uint8_t* src, const int32_t offset, uint8_t* dest,
                    uint8_t* tmp, uint8_t* tmp2) {
   blosc2_context* context = thread_context->parent_context;
@@ -772,6 +772,10 @@
     if (get_run(ip, ipbound)) {
       // A run.  Encode the repeated byte as a negative length in the length of the split.
       int32_t value = _src[j * neblock];
+      if (ntbytes > destsize) {
+        /* Not enough space to write out compressed block size */
+        return -1;
+      }
       _sw32(dest - 4, -value);
       continue;
     }
@@ -782,9 +786,9 @@
       maxout = (int32_t)snappy_max_compressed_length((size_t)neblock);
     }
   #endif /*  HAVE_SNAPPY */
-    if (ntbytes + maxout > maxbytes) {
+    if (ntbytes + maxout > destsize) {
       /* avoid buffer * overrun */
-      maxout = (int64_t)maxbytes - (int64_t)ntbytes;
+      maxout = (int64_t)destsize - (int64_t)ntbytes;
       if (maxout <= 0) {
         return 0;                  /* non-compressible block */
       }
@@ -859,7 +863,7 @@
         /* The compressor has been unable to compress data at all. */
         /* Before doing the copy, check that we are not running into a
            buffer overflow. */
-        if ((ntbytes + neblock) > maxbytes) {
+        if ((ntbytes + neblock) > destsize) {
           return 0;    /* Non-compressible data */
         }
         memcpy(dest, _src + j * neblock, (unsigned int)neblock);
```
