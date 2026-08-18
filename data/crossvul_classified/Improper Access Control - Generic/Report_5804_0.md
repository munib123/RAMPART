# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5804_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5804_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1127-1167 of the vulnerable file.

        err_status = "mk_augtemp";
        goto done;
    }
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        err_status = "open_augtemp";
        goto done;
    }

    if (augorig_exists) {
        if (transfer_file_attrs(augorig_canon_fp, fp, &err_status) != 0) {
            err_status = "xfer_attrs";
            goto done;
        }
    } else {
        /* Since mkstemp is used, the temp file will have secure permissions
         * instead of those implied by umask, so change them for new files */
        mode_t curumsk = umask(022);
        umask(curumsk);

        if (fchmod(fileno(fp), 0666 - curumsk) < 0) {
            err_status = "create_chmod";
            return -1;
        }
    }

    if (tree != NULL)
        lns_put(fp, lens, tree->children, text, &err);

    if (ferror(fp)) {
        err_status = "error_augtemp";
        goto done;
    }

    if (fflush(fp) != 0) {
        err_status = "flush_augtemp";
        goto done;
    }

    if (fsync(fileno(fp)) < 0) {
        err_status = "sync_augtemp";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1144,7 +1144,7 @@
         mode_t curumsk = umask(022);
         umask(curumsk);
 
-        if (fchmod(fileno(fp), 0666 - curumsk) < 0) {
+        if (fchmod(fileno(fp), 0666 & ~curumsk) < 0) {
             err_status = "create_chmod";
             return -1;
         }
```
