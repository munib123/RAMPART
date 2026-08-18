# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2628_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2628_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 124-164 of the vulnerable file.

        map_free(&msg_base, &msg_len);
        return;
    }

    prot_printf(out, "%%{");
    prot_printastring(out, dl->part);
    prot_printf(out, " ");
    prot_printastring(out, message_guid_encode(dl->gval));
    prot_printf(out, " %lu}\r\n", size);
    prot_write(out, msg_base, msg_len);
    fclose(f);
    map_free(&msg_base, &msg_len);
}

/* XXX - these two functions should be out in append.c or reserve.c
 * or something more general */
EXPORTED const char *dlist_reserve_path(const char *part, int isarchive,
                                        const struct message_guid *guid)
{
    static char buf[MAX_MAILBOX_PATH];
    const char *base;

    /* part can be either a configured partition name, or a path */
    if (strchr(part, '/')) {
        base = part;
    }
    else {
        base = isarchive ? config_archivepartitiondir(part)
                         : config_partitiondir(part);
    }

    /* we expect to have a base at this point, so let's assert that */
    assert(base != NULL);

    snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu/%s",
                  base, (unsigned long)getpid(),
                  message_guid_encode(guid));

    /* gotta make sure we can create files */
    if (cyrus_mkdir(buf, 0755)) {
        /* it's going to fail later, but at least this will help */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -141,16 +141,10 @@
                                         const struct message_guid *guid)
 {
     static char buf[MAX_MAILBOX_PATH];
-    const char *base;
-
-    /* part can be either a configured partition name, or a path */
-    if (strchr(part, '/')) {
-        base = part;
-    }
-    else {
-        base = isarchive ? config_archivepartitiondir(part)
-                         : config_partitiondir(part);
-    }
+
+    /* part must be a configured partition name on this server */
+    const char *base = isarchive ? config_archivepartitiondir(part)
+                                 : config_partitiondir(part);
 
     /* we expect to have a base at this point, so let's assert that */
     assert(base != NULL);
```
