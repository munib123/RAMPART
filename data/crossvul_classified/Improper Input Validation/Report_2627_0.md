# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2627_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2627_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2045-2085 of the vulnerable file.

                struct listargs listargs;

                c = getastring(imapd_in, imapd_out, &arg1);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg2);
                if (c != ' ') goto missingargs;
                c = getastring(imapd_in, imapd_out, &arg3);
                if (c == '\r') c = prot_getc(imapd_in);
                if (c != '\n') goto extraargs;

                memset(&listargs, 0, sizeof(struct listargs));
                listargs.ref = arg1.s;
                strarray_append(&listargs.pat, arg2.s);
                listargs.scan = arg3.s;

                cmd_list(tag.s, &listargs);

                snmp_increment(SCAN_COUNT, 1);
            }
            else if (!strcmp(cmd.s, "Syncapply")) {
                struct dlist *kl = sync_parseline(imapd_in);

                if (kl) {
                    cmd_syncapply(tag.s, kl, reserve_list);
                    dlist_free(&kl);
                }
                else goto extraargs;
            }
            else if (!strcmp(cmd.s, "Syncget")) {
                struct dlist *kl = sync_parseline(imapd_in);

                if (kl) {
                    cmd_syncget(tag.s, kl);
                    dlist_free(&kl);
                }
                else goto extraargs;
            }
            else if (!strcmp(cmd.s, "Syncrestart")) {
                if (c == '\r') c = prot_getc(imapd_in);
                if (c != '\n') goto extraargs;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2062,6 +2062,8 @@
                 snmp_increment(SCAN_COUNT, 1);
             }
             else if (!strcmp(cmd.s, "Syncapply")) {
+                if (!imapd_userisadmin) goto badcmd;
+
                 struct dlist *kl = sync_parseline(imapd_in);
 
                 if (kl) {
@@ -2071,6 +2073,8 @@
                 else goto extraargs;
             }
             else if (!strcmp(cmd.s, "Syncget")) {
+                if (!imapd_userisadmin) goto badcmd;
+
                 struct dlist *kl = sync_parseline(imapd_in);
 
                 if (kl) {
@@ -2080,6 +2084,8 @@
                 else goto extraargs;
             }
             else if (!strcmp(cmd.s, "Syncrestart")) {
+                if (!imapd_userisadmin) goto badcmd;
+
                 if (c == '\r') c = prot_getc(imapd_in);
                 if (c != '\n') goto extraargs;
 
@@ -2087,6 +2093,8 @@
                 cmd_syncrestart(tag.s, &reserve_list, 1);
             }
             else if (!strcmp(cmd.s, "Syncrestore")) {
+                if (!imapd_userisadmin) goto badcmd;
+
                 struct dlist *kl = sync_parseline(imapd_in);
 
                 if (kl) {
```
