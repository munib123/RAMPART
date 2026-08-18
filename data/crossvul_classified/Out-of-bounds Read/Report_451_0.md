# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 451_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `451_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 939-979 of the vulnerable file.

                uint8_t retval;
                int keylen;

                // get the record offset in the node
                rec_off =
                    tsk_getu16(fs->endian,
                    &node[nodesize - (rec + 1) * 2]);
                if (rec_off > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_cat_traverse: offset of record %d in index node %d too large (%d vs %"
                        PRIu16 ")", rec, cur_node, (int) rec_off,
                        nodesize);
                    free(node);
                    return 1;
                }

                key = (hfs_btree_key_cat *) & node[rec_off];

                keylen = 2 + tsk_getu16(hfs->fs_info.endian, key->key_len);
                if ((keylen) > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_cat_traverse: length of key %d in index node %d too large (%d vs %"
                        PRIu16 ")", rec, cur_node, keylen, nodesize);
                    free(node);
                    return 1;
                }


                /*
                   if (tsk_verbose)
                   tsk_fprintf(stderr,
                   "hfs_cat_traverse: record %" PRIu16
                   " ; keylen %" PRIu16 " (%" PRIu32 ")\n", rec,
                   tsk_getu16(fs->endian, key->key_len),
                   tsk_getu32(fs->endian, key->parent_cnid));
                 */


                /* save the info from this record unless it is too big */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -956,11 +956,12 @@
                 key = (hfs_btree_key_cat *) & node[rec_off];
 
                 keylen = 2 + tsk_getu16(hfs->fs_info.endian, key->key_len);
-                if ((keylen) > nodesize) {
+               
+                if (keylen >= nodesize - rec_off) {
                     tsk_error_set_errno(TSK_ERR_FS_GENFS);
                     tsk_error_set_errstr
                         ("hfs_cat_traverse: length of key %d in index node %d too large (%d vs %"
-                        PRIu16 ")", rec, cur_node, keylen, nodesize);
+                        PRIu16 ")", rec, cur_node, keylen, (nodesize - rec_off));
                     free(node);
                     return 1;
                 }
```
