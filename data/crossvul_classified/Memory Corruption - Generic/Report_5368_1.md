# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5368_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5368_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 52-92 of the vulnerable file.

 * than necessary.
 *
 * The major free Unix kernels have handled buffers like this since, like,
 * forever.
 */

static void socks_request_set_socks5_error(socks_request_t *req,
                              socks5_reply_status_t reason);

static int parse_socks(const char *data, size_t datalen, socks_request_t *req,
                       int log_sockstype, int safe_socks, ssize_t *drain_out,
                       size_t *want_length_out);
static int parse_socks_client(const uint8_t *data, size_t datalen,
                              int state, char **reason,
                              ssize_t *drain_out);

/* Chunk manipulation functions */

#define CHUNK_HEADER_LEN STRUCT_OFFSET(chunk_t, mem[0])

/** Return the number of bytes needed to allocate a chunk to hold
 * <b>memlen</b> bytes. */
#define CHUNK_ALLOC_SIZE(memlen) (CHUNK_HEADER_LEN + (memlen))
/** Return the number of usable bytes in a chunk allocated with
 * malloc(<b>memlen</b>). */
#define CHUNK_SIZE_WITH_ALLOC(memlen) ((memlen) - CHUNK_HEADER_LEN)

/** Return the next character in <b>chunk</b> onto which data can be appended.
 * If the chunk is full, this might be off the end of chunk->mem. */
static INLINE char *
CHUNK_WRITE_PTR(chunk_t *chunk)
{
  return chunk->data + chunk->datalen;
}

/** Return the number of bytes that can be written onto <b>chunk</b> without
 * running out of space. */
static INLINE size_t
CHUNK_REMAINING_CAPACITY(const chunk_t *chunk)
{
  return (chunk->mem + chunk->memlen) - (chunk->data + chunk->datalen);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -69,12 +69,33 @@
 
 #define CHUNK_HEADER_LEN STRUCT_OFFSET(chunk_t, mem[0])
 
+/* We leave this many NUL bytes at the end of the buffer. */
+#define SENTINEL_LEN 4
+
+/* Header size plus NUL bytes at the end */
+#define CHUNK_OVERHEAD (CHUNK_HEADER_LEN + SENTINEL_LEN)
+
 /** Return the number of bytes needed to allocate a chunk to hold
  * <b>memlen</b> bytes. */
-#define CHUNK_ALLOC_SIZE(memlen) (CHUNK_HEADER_LEN + (memlen))
+#define CHUNK_ALLOC_SIZE(memlen) (CHUNK_OVERHEAD + (memlen))
 /** Return the number of usable bytes in a chunk allocated with
  * malloc(<b>memlen</b>). */
-#define CHUNK_SIZE_WITH_ALLOC(memlen) ((memlen) - CHUNK_HEADER_LEN)
+#define CHUNK_SIZE_WITH_ALLOC(memlen) ((memlen) - CHUNK_OVERHEAD)
+
+#define DEBUG_SENTINEL
+
+#ifdef DEBUG_SENTINEL
+#define DBG_S(s) s
+#else
+#define DBG_S(s) (void)0
+#endif
+
+#define CHUNK_SET_SENTINEL(chunk, alloclen) do {                        \
+    uint8_t *a = (uint8_t*) &(chunk)->mem[(chunk)->memlen];             \
+    DBG_S(uint8_t *b = &((uint8_t*)(chunk))[(alloclen)-SENTINEL_LEN]);  \
+    DBG_S(tor_assert(a == b));                                          \
+    memset(a,0,SENTINEL_LEN);                                           \
+  } while (0)
 
 /** Return the next character in <b>chunk</b> onto which data can be appended.
  * If the chunk is full, this might be off the end of chunk->mem. */
@@ -131,6 +152,7 @@
   ch->memlen = CHUNK_SIZE_WITH_ALLOC(alloc);
   total_bytes_allocated_in_chunks += alloc;
   ch->data = &ch->mem[0];
+  CHUNK_SET_SENTINEL(ch, alloc);
   return ch;
 }
 
@@ -140,18 +162,20 @@
 chunk_grow(chunk_t *chunk, size_t sz)
 {
   off_t offset;
-  size_t memlen_orig = chunk->memlen;
+  const size_t memlen_orig = chunk->memlen;
+  const size_t orig_alloc = CHUNK_ALLOC_SIZE(memlen_orig);
+  const size_t new_alloc = CHUNK_ALLOC_SIZE(sz);
   tor_assert(sz > chunk->memlen);
   offset = chunk->data - chunk->mem;
-  chunk = tor_realloc(chunk, CHUNK_ALLOC_SIZE(sz));
+  chunk = tor_realloc(chunk, new_alloc);
   chunk->memlen = sz;
   chunk->data = chunk->mem + offset;
 #ifdef DEBUG_CHUNK_ALLOC
-  tor_assert(chunk->DBG_alloc == CHUNK_ALLOC_SIZE(memlen_orig));
-  chunk->DBG_alloc = CHUNK_ALLOC_SIZE(sz);
+  tor_assert(chunk->DBG_alloc == orig_alloc);
+  chunk->DBG_alloc = new_alloc;
 #endif
-  total_bytes_allocated_in_chunks +=
-    CHUNK_ALLOC_SIZE(sz) - CHUNK_ALLOC_SIZE(memlen_orig);
+  total_bytes_allocated_in_chunks += new_alloc - orig_alloc;
+  CHUNK_SET_SENTINEL(chunk, new_alloc);
   return chunk;
 }
 
```
