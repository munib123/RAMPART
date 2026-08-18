# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 255_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `255_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 698-738 of the vulnerable file.


  cache_expand(file, sizeof(file), &nserv->conn->account, ".active");
  mutt_debug(1, "Updating %s\n", file);
  rc = update_file(file, buf);
  FREE(&buf);
  return rc;
}

#ifdef USE_HCACHE
/**
 * nntp_hcache_namer - Compose hcache file names
 * @param path    Path of message
 * @param dest    Buffer for filename
 * @param destlen Length of buffer
 * @retval num Characters written to buffer
 *
 * Used by mutt_hcache_open() to compose hcache file name
 */
static int nntp_hcache_namer(const char *path, char *dest, size_t destlen)
{
  return snprintf(dest, destlen, "%s.hcache", path);
}

/**
 * nntp_hcache_open - Open newsgroup hcache
 * @param nntp_data NNTP data
 * @retval ptr  Header cache
 * @retval NULL Error
 */
header_cache_t *nntp_hcache_open(struct NntpData *nntp_data)
{
  struct Url url;
  char file[PATH_MAX];

  if (!nntp_data->nserv || !nntp_data->nserv->cacheable ||
      !nntp_data->nserv->conn || !nntp_data->group ||
      !(nntp_data->newsrc_ent || nntp_data->subscribed || SaveUnsubscribed))
  {
    return NULL;
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -715,7 +715,18 @@
  */
 static int nntp_hcache_namer(const char *path, char *dest, size_t destlen)
 {
-  return snprintf(dest, destlen, "%s.hcache", path);
+  int count = snprintf(dest, destlen, "%s.hcache", path);
+
+  /* Strip out any directories in the path */
+  char *first = strchr(dest, '/');
+  char *last = strrchr(dest, '/');
+  if (first && last && (last > first))
+  {
+    memmove(first, last, strlen(last) + 1);
+    count -= (last - first);
+  }
+
+  return count;
 }
 
 /**
```
