# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5496_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5496_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 185-225 of the vulnerable file.

	}
	if (i == nsbuf) {
		kmem_free(sbuf);
		return 0;
	}

	/*
	 * Loop putting entries into the user buffer.
	 */
	for ( ; i < nsbuf; i++, sbp++) {
		if (cursor->hashval != sbp->hash) {
			cursor->hashval = sbp->hash;
			cursor->offset = 0;
		}
		error = context->put_listent(context,
					sbp->flags,
					sbp->name,
					sbp->namelen,
					sbp->valuelen,
					&sbp->name[sbp->namelen]);
		if (error)
			return error;
		if (context->seen_enough)
			break;
		cursor->offset++;
	}

	kmem_free(sbuf);
	return 0;
}

STATIC int
xfs_attr_node_list(xfs_attr_list_context_t *context)
{
	attrlist_cursor_kern_t *cursor;
	xfs_attr_leafblock_t *leaf;
	xfs_da_intnode_t *node;
	struct xfs_attr3_icleaf_hdr leafhdr;
	struct xfs_da3_icnode_hdr nodehdr;
	struct xfs_da_node_entry *btree;
	int error, i;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,8 +202,10 @@
 					sbp->namelen,
 					sbp->valuelen,
 					&sbp->name[sbp->namelen]);
-		if (error)
+		if (error) {
+			kmem_free(sbuf);
 			return error;
+		}
 		if (context->seen_enough)
 			break;
 		cursor->offset++;
@@ -454,14 +456,13 @@
 				args.rmtblkcnt = xfs_attr3_rmt_blocks(
 							args.dp->i_mount, valuelen);
 				retval = xfs_attr_rmtval_get(&args);
-				if (retval)
-					return retval;
-				retval = context->put_listent(context,
-						entry->flags,
-						name_rmt->name,
-						(int)name_rmt->namelen,
-						valuelen,
-						args.value);
+				if (!retval)
+					retval = context->put_listent(context,
+							entry->flags,
+							name_rmt->name,
+							(int)name_rmt->namelen,
+							valuelen,
+							args.value);
 				kmem_free(args.value);
 			} else {
 				retval = context->put_listent(context,
```
