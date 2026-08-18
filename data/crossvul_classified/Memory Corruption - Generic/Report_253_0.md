# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 253_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `253_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 575-615 of the vulnerable file.

void nntp_expand_path(char *line, size_t len, struct Account *acct)
{
  struct Url url;

  mutt_account_tourl(acct, &url);
  url.path = mutt_str_strdup(line);
  url_tostring(&url, line, len, 0);
  FREE(&url.path);
}

/**
 * nntp_add_group - Parse newsgroup
 * @param line String to parse
 * @param data NNTP data
 * @retval 0 Always
 */
int nntp_add_group(char *line, void *data)
{
  struct NntpServer *nserv = data;
  struct NntpData *nntp_data = NULL;
  char group[LONG_STRING];
  char desc[HUGE_STRING] = "";
  char mod;
  anum_t first, last;

  if (!nserv || !line)
    return 0;

  if (sscanf(line, "%s " ANUM " " ANUM " %c %[^\n]", group, &last, &first, &mod, desc) < 4)
    return 0;

  nntp_data = nntp_data_find(nserv, group);
  nntp_data->deleted = false;
  nntp_data->first_message = first;
  nntp_data->last_message = last;
  nntp_data->allowed = (mod == 'y') || (mod == 'm');
  mutt_str_replace(&nntp_data->desc, desc);
  if (nntp_data->newsrc_ent || nntp_data->last_cached)
    nntp_group_unread_stat(nntp_data);
  else if (nntp_data->last_message && nntp_data->first_message <= nntp_data->last_message)
    nntp_data->unread = nntp_data->last_message - nntp_data->first_message + 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -592,7 +592,7 @@
 {
   struct NntpServer *nserv = data;
   struct NntpData *nntp_data = NULL;
-  char group[LONG_STRING];
+  char group[LONG_STRING] = "";
   char desc[HUGE_STRING] = "";
   char mod;
   anum_t first, last;
@@ -600,8 +600,12 @@
   if (!nserv || !line)
     return 0;
 
-  if (sscanf(line, "%s " ANUM " " ANUM " %c %[^\n]", group, &last, &first, &mod, desc) < 4)
+  /* These sscanf limits must match the sizes of the group and desc arrays */
+  if (sscanf(line, "%1023s " ANUM " " ANUM " %c %8191[^\n]", group, &last, &first, &mod, desc) < 4)
+  {
+    mutt_debug(4, "Cannot parse server line: %s\n", line);
     return 0;
+  }
 
   nntp_data = nntp_data_find(nserv, group);
   nntp_data->deleted = false;
```
