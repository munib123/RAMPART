# CrossVul Fix Pair: Improper Check for Unusual or Exceptional Conditions in c
**Pair ID:** 431_0
**Vulnerability Class:** Improper Check for Unusual or Exceptional Conditions
**CWE:** CWE-754
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `431_0`)

## Vulnerability Information & PoC

## Description
Improper Check for Unusual or Exceptional Conditions - The programmer may assume that certain events or conditions will never occur or do not need to be worried about, such as low memory conditions, lack of access to resources due to restrictive permis...

## Vulnerable Code
```c
Lines 494-534 of the vulnerable file.

 *========================================================================*/

/*
 * Add a name to the shortform attribute list structure
 * This is the external routine.
 */
STATIC int
xfs_attr_shortform_addname(xfs_da_args_t *args)
{
	int newsize, forkoff, retval;

	trace_xfs_attr_sf_addname(args);

	retval = xfs_attr_shortform_lookup(args);
	if ((args->flags & ATTR_REPLACE) && (retval == -ENOATTR)) {
		return retval;
	} else if (retval == -EEXIST) {
		if (args->flags & ATTR_CREATE)
			return retval;
		retval = xfs_attr_shortform_remove(args);
		ASSERT(retval == 0);
	}

	if (args->namelen >= XFS_ATTR_SF_ENTSIZE_MAX ||
	    args->valuelen >= XFS_ATTR_SF_ENTSIZE_MAX)
		return -ENOSPC;

	newsize = XFS_ATTR_SF_TOTSIZE(args->dp);
	newsize += XFS_ATTR_SF_ENTSIZE_BYNAME(args->namelen, args->valuelen);

	forkoff = xfs_attr_shortform_bytesfit(args->dp, newsize);
	if (!forkoff)
		return -ENOSPC;

	xfs_attr_shortform_add(args, forkoff);
	return 0;
}


/*========================================================================
 * External routines when attribute list is one block
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -511,7 +511,14 @@
 		if (args->flags & ATTR_CREATE)
 			return retval;
 		retval = xfs_attr_shortform_remove(args);
-		ASSERT(retval == 0);
+		if (retval)
+			return retval;
+		/*
+		 * Since we have removed the old attr, clear ATTR_REPLACE so
+		 * that the leaf format add routine won't trip over the attr
+		 * not being around.
+		 */
+		args->flags &= ~ATTR_REPLACE;
 	}
 
 	if (args->namelen >= XFS_ATTR_SF_ENTSIZE_MAX ||
```
