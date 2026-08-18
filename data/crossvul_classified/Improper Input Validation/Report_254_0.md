# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 254_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `254_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1271-1311 of the vulnerable file.

  struct Header *hdr = NULL;
  char buf[HUGE_STRING];
  int rc = 0;
  int oldmsgcount = ctx->msgcount;
  anum_t current;
  anum_t first_over = first;
#ifdef USE_HCACHE
  void *hdata = NULL;
#endif

  /* if empty group or nothing to do */
  if (!last || first > last)
    return 0;

  /* init fetch context */
  fc.ctx = ctx;
  fc.first = first;
  fc.last = last;
  fc.restore = restore;
  fc.messages = mutt_mem_calloc(last - first + 1, sizeof(unsigned char));
#ifdef USE_HCACHE
  fc.hc = hc;
#endif

  /* fetch list of articles */
  if (NntpListgroup && nntp_data->nserv->hasLISTGROUP && !nntp_data->deleted)
  {
    if (!ctx->quiet)
      mutt_message(_("Fetching list of articles..."));
    if (nntp_data->nserv->hasLISTGROUPrange)
      snprintf(buf, sizeof(buf), "LISTGROUP %s %u-%u\r\n", nntp_data->group, first, last);
    else
      snprintf(buf, sizeof(buf), "LISTGROUP %s\r\n", nntp_data->group);
    rc = nntp_fetch_lines(nntp_data, buf, sizeof(buf), NULL, fetch_numbers, &fc);
    if (rc > 0)
    {
      mutt_error("LISTGROUP: %s", buf);
    }
    if (rc == 0)
    {
      for (current = first; current <= last && rc == 0; current++)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1288,6 +1288,8 @@
   fc.last = last;
   fc.restore = restore;
   fc.messages = mutt_mem_calloc(last - first + 1, sizeof(unsigned char));
+  if (fc.messages == NULL)
+	  return -1;
 #ifdef USE_HCACHE
   fc.hc = hc;
 #endif
```
