# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5728_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5728_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 3262-3303 of the vulnerable file.

/*
 * cifs_build_path_to_root returns full path to root when we do not have an
 * exiting connection (tcon)
 */
static char *
build_unc_path_to_root(const struct smb_vol *vol,
		const struct cifs_sb_info *cifs_sb)
{
	char *full_path, *pos;
	unsigned int pplen = vol->prepath ? strlen(vol->prepath) + 1 : 0;
	unsigned int unc_len = strnlen(vol->UNC, MAX_TREE_SIZE + 1);

	full_path = kmalloc(unc_len + pplen + 1, GFP_KERNEL);
	if (full_path == NULL)
		return ERR_PTR(-ENOMEM);

	strncpy(full_path, vol->UNC, unc_len);
	pos = full_path + unc_len;

	if (pplen) {
		*pos++ = CIFS_DIR_SEP(cifs_sb);
		strncpy(pos, vol->prepath, pplen);
		pos += pplen;
	}

	*pos = '\0'; /* add trailing null */
	convert_delimiter(full_path, CIFS_DIR_SEP(cifs_sb));
	cifs_dbg(FYI, "%s: full_path=%s\n", __func__, full_path);
	return full_path;
}

/*
 * Perform a dfs referral query for a share and (optionally) prefix
 *
 * If a referral is found, cifs_sb->mountdata will be (re-)allocated
 * to a string containing updated options for the submount.  Otherwise it
 * will be left untouched.
 *
 * Returns the rc from get_dfs_path to the caller, which can be used to
 * determine whether there were referrals.
 */
static int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3279,8 +3279,8 @@
 	pos = full_path + unc_len;
 
 	if (pplen) {
-		*pos++ = CIFS_DIR_SEP(cifs_sb);
-		strncpy(pos, vol->prepath, pplen);
+		*pos = CIFS_DIR_SEP(cifs_sb);
+		strncpy(pos + 1, vol->prepath, pplen);
 		pos += pplen;
 	}
 
```
