# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2789_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2789_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2834-2874 of the vulnerable file.


            /* special case any other altprefix stuff */
            rock->mb_category = MBNAME_ALTPREFIX;
            r = cyrusdb_foreach(rock->db, inbox, inboxlen+1, &find_p, &find_cb, rock, NULL);
        skipalt: /* we got a done, so skip out of the foreach early */
            if (r == CYRUSDB_DONE) r = 0;
            if (r) goto done;
        }
    }

    /*
     * Other Users namespace
     *
     * If "Other Users*" can match pattern, search for those mailboxes next
     */
    if (isadmin || rock->namespace->accessible[NAMESPACE_USER]) {
        len = strlen(rock->namespace->prefix[NAMESPACE_USER]);
        if (len) len--; // trailing separator

        if (!strncmp(rock->namespace->prefix[NAMESPACE_USER], commonpat, MIN(len, prefixlen))) {
            if (prefixlen < len) {
                /* we match all users */
                strlcpy(domainpat+domainlen, "user.", sizeof(domainpat)-domainlen);
            }
            else {
                /* just those in this prefix */
                strlcpy(domainpat+domainlen, "user.", sizeof(domainpat)-domainlen);
                strlcpy(domainpat+domainlen+5, commonpat+len+1, sizeof(domainpat)-domainlen-5);
            }

            rock->mb_category = MBNAME_OTHERUSER;

            /* because of how domains work, with crossdomains or admin you can't prefix at all :( */
            size_t thislen = (isadmin || crossdomains) ? 0 : strlen(domainpat);

            /* reset the the namebuffer */
            r = (*rock->proc)(NULL, rock->procrock);
            if (r) goto done;

            r = mboxlist_find_category(rock, domainpat, thislen);
            if (r) goto done;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2851,7 +2851,7 @@
         if (len) len--; // trailing separator
 
         if (!strncmp(rock->namespace->prefix[NAMESPACE_USER], commonpat, MIN(len, prefixlen))) {
-            if (prefixlen < len) {
+            if (prefixlen <= len) {
                 /* we match all users */
                 strlcpy(domainpat+domainlen, "user.", sizeof(domainpat)-domainlen);
             }
```
