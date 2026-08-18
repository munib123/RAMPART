# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 711_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `711_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 920-960 of the vulnerable file.

                cur_node, cur_off, num_rec);

        if (num_rec == 0) {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr("hfs_cat_traverse: zero records in node %"
                PRIu32, cur_node);
            free(node);
            return 1;
        }

        /* With an index node, find the record with the largest key that is smaller
         * to or equal to cnid */
        if (node_desc->type == HFS_BT_NODE_TYPE_IDX) {
            uint32_t next_node = 0;
            int rec;

            for (rec = 0; rec < num_rec; ++rec) {
                size_t rec_off;
                hfs_btree_key_cat *key;
                uint8_t retval;
                uint16_t keylen;

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -937,7 +937,7 @@
                 size_t rec_off;
                 hfs_btree_key_cat *key;
                 uint8_t retval;
-                uint16_t keylen;
+                int keylen;
 
                 // get the record offset in the node
                 rec_off =
@@ -1042,7 +1042,7 @@
                 size_t rec_off;
                 hfs_btree_key_cat *key;
                 uint8_t retval;
-                uint16_t keylen;
+                int keylen;
 
                 // get the record offset in the node
                 rec_off =
```
