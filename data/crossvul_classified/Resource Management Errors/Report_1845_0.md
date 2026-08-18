# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1845_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1845_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.

	if (err)
		goto out_cleanup;

	ovl_dentry_update(dentry, newdentry);
	newdentry = NULL;

	/*
	 * Non-directores become opaque when copied up.
	 */
	if (!S_ISDIR(stat->mode))
		ovl_dentry_set_opaque(dentry, true);
out2:
	dput(upper);
out1:
	dput(newdentry);
out:
	return err;

out_cleanup:
	ovl_cleanup(wdir, newdentry);
	goto out;
}

/*
 * Copy up a single dentry
 *
 * Directory renames only allowed on "pure upper" (already created on
 * upper filesystem, never copied up).  Directories which are on lower or
 * are merged may not be renamed.  For these -EXDEV is returned and
 * userspace has to deal with it.  This means, when copying up a
 * directory we can rely on it and ancestors being stable.
 *
 * Non-directory renames start with copy up of source if necessary.  The
 * actual rename will only proceed once the copy up was successful.  Copy
 * up uses upper parent i_mutex for exclusion.  Since rename can change
 * d_parent it is possible that the copy up will lock the old parent.  At
 * that point the file will have already been copied up anyway.
 */
int ovl_copy_up_one(struct dentry *parent, struct dentry *dentry,
		    struct path *lowerpath, struct kstat *stat,
		    struct iattr *attr)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,7 +267,7 @@
 
 out_cleanup:
 	ovl_cleanup(wdir, newdentry);
-	goto out;
+	goto out2;
 }
 
 /*
```
