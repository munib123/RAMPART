# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 249_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `249_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 227-267 of the vulnerable file.

 * @retval ptr HeaderCache
 * @retval NULL Failure
 */
header_cache_t *imap_hcache_open(struct ImapData *idata, const char *path)
{
  struct ImapMbox mx;
  struct Url url;
  char cachepath[PATH_MAX];
  char mbox[PATH_MAX];

  if (path)
    imap_cachepath(idata, path, mbox, sizeof(mbox));
  else
  {
    if (!idata->ctx || imap_parse_path(idata->ctx->path, &mx) < 0)
      return NULL;

    imap_cachepath(idata, mx.mbox, mbox, sizeof(mbox));
    FREE(&mx.mbox);
  }

  mutt_account_tourl(&idata->conn->account, &url);
  url.path = mbox;
  url_tostring(&url, cachepath, sizeof(cachepath), U_PATH);

  return mutt_hcache_open(HeaderCache, cachepath, imap_hcache_namer);
}

/**
 * imap_hcache_close - Close the header cache
 * @param idata Server data
 */
void imap_hcache_close(struct ImapData *idata)
{
  if (!idata->hcache)
    return;

  mutt_hcache_close(idata->hcache);
  idata->hcache = NULL;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,6 +245,12 @@
     FREE(&mx.mbox);
   }
 
+  if (strstr(mbox, "/../") || (strcmp(mbox, "..") == 0) || (strncmp(mbox, "../", 3) == 0))
+    return NULL;
+  size_t len = strlen(mbox);
+  if ((len > 3) && (strcmp(mbox + len - 3, "/..") == 0))
+    return NULL;
+
   mutt_account_tourl(&idata->conn->account, &url);
   url.path = mbox;
   url_tostring(&url, cachepath, sizeof(cachepath), U_PATH);
```
