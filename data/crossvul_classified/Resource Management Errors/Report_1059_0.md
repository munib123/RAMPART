# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1059_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1059_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 349-389 of the vulnerable file.

		start = end = GENL_ID_PMCRAID;
	} else if (strcmp(family->name, "VFS_DQUOT") == 0) {
		start = end = GENL_ID_VFS_DQUOT;
	}

	if (family->maxattr && !family->parallel_ops) {
		family->attrbuf = kmalloc_array(family->maxattr + 1,
						sizeof(struct nlattr *),
						GFP_KERNEL);
		if (family->attrbuf == NULL) {
			err = -ENOMEM;
			goto errout_locked;
		}
	} else
		family->attrbuf = NULL;

	family->id = idr_alloc(&genl_fam_idr, family,
			       start, end + 1, GFP_KERNEL);
	if (family->id < 0) {
		err = family->id;
		goto errout_locked;
	}

	err = genl_validate_assign_mc_groups(family);
	if (err)
		goto errout_remove;

	genl_unlock_all();

	/* send all events */
	genl_ctrl_event(CTRL_CMD_NEWFAMILY, family, NULL, 0);
	for (i = 0; i < family->n_mcgrps; i++)
		genl_ctrl_event(CTRL_CMD_NEWMCAST_GRP, family,
				&family->mcgrps[i], family->mcgrp_offset + i);

	return 0;

errout_remove:
	idr_remove(&genl_fam_idr, family->id);
	kfree(family->attrbuf);
errout_locked:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -366,7 +366,7 @@
 			       start, end + 1, GFP_KERNEL);
 	if (family->id < 0) {
 		err = family->id;
-		goto errout_locked;
+		goto errout_free;
 	}
 
 	err = genl_validate_assign_mc_groups(family);
@@ -385,6 +385,7 @@
 
 errout_remove:
 	idr_remove(&genl_fam_idr, family->id);
+errout_free:
 	kfree(family->attrbuf);
 errout_locked:
 	genl_unlock_all();
```
