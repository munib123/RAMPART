# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 255_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `255_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 45-85 of the vulnerable file.

#include "globals.h"
#include "header.h"
#include "mailbox.h"
#include "mutt_account.h"
#include "mutt_curses.h"
#include "mutt_socket.h"
#include "mx.h"
#include "ncrypt/ncrypt.h"
#include "options.h"
#include "progress.h"
#include "protos.h"
#include "url.h"
#ifdef USE_HCACHE
#include "hcache/hcache.h"
#endif

#ifdef USE_HCACHE
#define HC_FNAME "neomutt" /* filename for hcache as POP lacks paths */
#define HC_FEXT "hcache"   /* extension for hcache as POP lacks paths */
#endif

/**
 * fetch_message - write line to file
 * @param line String to write
 * @param file FILE pointer to write to
 * @retval  0 Success
 * @retval -1 Failure
 */
static int fetch_message(char *line, void *file)
{
  FILE *f = (FILE *) file;

  fputs(line, f);
  if (fputc('\n', f) == EOF)
    return -1;

  return 0;
}

/**
 * pop_read_header - Read header
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -64,6 +64,23 @@
 #endif
 
 /**
+ * cache_id - Make a message-cache-compatible id
+ * @param id POP message id
+ * @retval ptr Sanitised string
+ *
+ * The POP message id may contain '/' and other awkward characters.
+ *
+ * @note This function returns a pointer to a static buffer.
+ */
+static const char *cache_id(const char *id)
+{
+  static char clean[SHORT_STRING];
+  mutt_str_strfcpy(clean, id, sizeof(clean));
+  mutt_file_sanitize_filename(clean, true);
+  return clean;
+}
+
+/**
  * fetch_message - write line to file
  * @param line String to write
  * @param file FILE pointer to write to
@@ -242,7 +259,7 @@
   /* message not found in context -> remove it from cache
    * return the result of bcache, so we stop upon its first error
    */
-  return mutt_bcache_del(bcache, id);
+  return mutt_bcache_del(bcache, cache_id(id));
 }
 
 #ifdef USE_HCACHE
@@ -407,7 +424,7 @@
        *        - if we don't have a body: new
        */
       const bool bcached =
-          (mutt_bcache_exists(pop_data->bcache, ctx->hdrs[i]->data) == 0);
+          (mutt_bcache_exists(pop_data->bcache, cache_id(ctx->hdrs[i]->data)) == 0);
       ctx->hdrs[i]->old = false;
       ctx->hdrs[i]->read = false;
       if (hcached)
@@ -597,7 +614,7 @@
   unsigned short bcache = 1;
 
   /* see if we already have the message in body cache */
-  msg->fp = mutt_bcache_get(pop_data->bcache, h->data);
+  msg->fp = mutt_bcache_get(pop_data->bcache, cache_id(h->data));
   if (msg->fp)
     return 0;
 
@@ -644,7 +661,7 @@
                        NetInc, h->content->length + h->content->offset - 1);
 
     /* see if we can put in body cache; use our cache as fallback */
-    msg->fp = mutt_bcache_put(pop_data->bcache, h->data);
+    msg->fp = mutt_bcache_put(pop_data->bcache, cache_id(h->data));
     if (!msg->fp)
     {
       /* no */
@@ -689,7 +706,7 @@
    * portion of the headers, those required for the main display.
    */
   if (bcache)
-    mutt_bcache_commit(pop_data->bcache, h->data);
+    mutt_bcache_commit(pop_data->bcache, cache_id(h->data));
   else
   {
     cache->index = h->index;
@@ -783,7 +800,7 @@
         ret = pop_query(pop_data, buf, sizeof(buf));
         if (ret == 0)
         {
-          mutt_bcache_del(pop_data->bcache, ctx->hdrs[i]->data);
+          mutt_bcache_del(pop_data->bcache, cache_id(ctx->hdrs[i]->data));
 #ifdef USE_HCACHE
           mutt_hcache_delete(hc, ctx->hdrs[i]->data, strlen(ctx->hdrs[i]->data));
 #endif
```
