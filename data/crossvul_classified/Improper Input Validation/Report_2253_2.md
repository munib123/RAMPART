# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2253_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2253_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 203-243 of the vulnerable file.

    if (fd == -1) {
        return -1;
    }

    /* If chains are full, just return the new FD, bad luck... */
    if (ht->av_slots <= 0) {
        return fd;
    }

    /* Register the new entry in an available slot */
    for (i = 0; i < VHOST_FDT_HASHTABLE_CHAINS; i++) {
        hc = &ht->chain[i];
        if (hc->fd == -1) {
            hc->fd   = fd;
            hc->hash = hash;
            hc->readers++;
            ht->av_slots--;

            sr->vhost_fdt_id   = id;
            sr->vhost_fdt_hash = hash;

            return fd;
        }
    }

    return -1;
}

static inline int mk_vhost_fdt_close(struct session_request *sr)
{
    int id;
    unsigned int hash;
    struct vhost_fdt_hash_table *ht = NULL;
    struct vhost_fdt_hash_chain *hc;

    if (config->fdt == MK_FALSE) {
        return close(sr->fd_file);
    }

    id   = sr->vhost_fdt_id;
    hash = sr->vhost_fdt_hash;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -220,6 +220,7 @@
 
             sr->vhost_fdt_id   = id;
             sr->vhost_fdt_hash = hash;
+            sr->fd_is_fdt      = MK_TRUE;
 
             return fd;
         }
@@ -262,7 +263,6 @@
             return 0;
         }
     }
-
     return close(sr->fd_file);
 }
 
```
