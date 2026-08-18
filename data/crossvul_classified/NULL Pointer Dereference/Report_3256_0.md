# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3256_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3256_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 310-350 of the vulnerable file.

 */
int fscrypt_decrypt_page(const struct inode *inode, struct page *page,
			unsigned int len, unsigned int offs, u64 lblk_num)
{
	if (!(inode->i_sb->s_cop->flags & FS_CFLG_OWN_PAGES))
		BUG_ON(!PageLocked(page));

	return fscrypt_do_page_crypto(inode, FS_DECRYPT, lblk_num, page, page,
				      len, offs, GFP_NOFS);
}
EXPORT_SYMBOL(fscrypt_decrypt_page);

/*
 * Validate dentries for encrypted directories to make sure we aren't
 * potentially caching stale data after a key has been added or
 * removed.
 */
static int fscrypt_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *dir;
	struct fscrypt_info *ci;
	int dir_has_key, cached_with_key;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	dir = dget_parent(dentry);
	if (!d_inode(dir)->i_sb->s_cop->is_encrypted(d_inode(dir))) {
		dput(dir);
		return 0;
	}

	ci = d_inode(dir)->i_crypt_info;
	if (ci && ci->ci_keyring_key &&
	    (ci->ci_keyring_key->flags & ((1 << KEY_FLAG_INVALIDATED) |
					  (1 << KEY_FLAG_REVOKED) |
					  (1 << KEY_FLAG_DEAD))))
		ci = NULL;

	/* this should eventually be an flag in d_flags */
	spin_lock(&dentry->d_lock);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -327,7 +327,6 @@
 static int fscrypt_d_revalidate(struct dentry *dentry, unsigned int flags)
 {
 	struct dentry *dir;
-	struct fscrypt_info *ci;
 	int dir_has_key, cached_with_key;
 
 	if (flags & LOOKUP_RCU)
@@ -339,18 +338,11 @@
 		return 0;
 	}
 
-	ci = d_inode(dir)->i_crypt_info;
-	if (ci && ci->ci_keyring_key &&
-	    (ci->ci_keyring_key->flags & ((1 << KEY_FLAG_INVALIDATED) |
-					  (1 << KEY_FLAG_REVOKED) |
-					  (1 << KEY_FLAG_DEAD))))
-		ci = NULL;
-
 	/* this should eventually be an flag in d_flags */
 	spin_lock(&dentry->d_lock);
 	cached_with_key = dentry->d_flags & DCACHE_ENCRYPTED_WITH_KEY;
 	spin_unlock(&dentry->d_lock);
-	dir_has_key = (ci != NULL);
+	dir_has_key = (d_inode(dir)->i_crypt_info != NULL);
 	dput(dir);
 
 	/*
```
