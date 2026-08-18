# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 576_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `576_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 313-353 of the vulnerable file.


    /*
     * Argument sanity checking, and opening up the DB
     */
    if (entry == NULL)
        return EINVAL;
    if(!(mask & KADM5_PRINCIPAL) || (mask & KADM5_MOD_NAME) ||
       (mask & KADM5_MOD_TIME) || (mask & KADM5_LAST_PWD_CHANGE) ||
       (mask & KADM5_MKVNO) || (mask & KADM5_AUX_ATTRIBUTES) ||
       (mask & KADM5_LAST_SUCCESS) || (mask & KADM5_LAST_FAILED) ||
       (mask & KADM5_FAIL_AUTH_COUNT))
        return KADM5_BAD_MASK;
    if ((mask & KADM5_KEY_DATA) && entry->n_key_data != 0)
        return KADM5_BAD_MASK;
    if((mask & KADM5_POLICY) && entry->policy == NULL)
        return KADM5_BAD_MASK;
    if((mask & KADM5_POLICY) && (mask & KADM5_POLICY_CLR))
        return KADM5_BAD_MASK;
    if((mask & ~ALL_PRINC_MASK))
        return KADM5_BAD_MASK;

    /*
     * Check to see if the principal exists
     */
    ret = kdb_get_entry(handle, entry->principal, &kdb, &adb);

    switch(ret) {
    case KADM5_UNK_PRINC:
        break;
    case 0:
        kdb_free_entry(handle, kdb, &adb);
        return KADM5_DUP;
    default:
        return ret;
    }

    kdb = calloc(1, sizeof(*kdb));
    if (kdb == NULL)
        return ENOMEM;
    memset(&adb, 0, sizeof(osa_princ_ent_rec));

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -330,6 +330,13 @@
         return KADM5_BAD_MASK;
     if((mask & ~ALL_PRINC_MASK))
         return KADM5_BAD_MASK;
+    if (mask & KADM5_TL_DATA) {
+        for (tl_data_tail = entry->tl_data; tl_data_tail != NULL;
+             tl_data_tail = tl_data_tail->tl_data_next) {
+            if (tl_data_tail->tl_data_type < 256)
+                return KADM5_BAD_TL_TYPE;
+        }
+    }
 
     /*
      * Check to see if the principal exists
```
