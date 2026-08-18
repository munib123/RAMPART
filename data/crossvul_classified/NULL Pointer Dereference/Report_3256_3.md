# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3256_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3256_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 78-118 of the vulnerable file.

static int validate_user_key(struct fscrypt_info *crypt_info,
			struct fscrypt_context *ctx, u8 *raw_key,
			const char *prefix)
{
	char *description;
	struct key *keyring_key;
	struct fscrypt_key *master_key;
	const struct user_key_payload *ukp;
	int res;

	description = kasprintf(GFP_NOFS, "%s%*phN", prefix,
				FS_KEY_DESCRIPTOR_SIZE,
				ctx->master_key_descriptor);
	if (!description)
		return -ENOMEM;

	keyring_key = request_key(&key_type_logon, description, NULL);
	kfree(description);
	if (IS_ERR(keyring_key))
		return PTR_ERR(keyring_key);

	if (keyring_key->type != &key_type_logon) {
		printk_once(KERN_WARNING
				"%s: key type must be logon\n", __func__);
		res = -ENOKEY;
		goto out;
	}
	down_read(&keyring_key->sem);
	ukp = user_key_payload(keyring_key);
	if (ukp->datalen != sizeof(struct fscrypt_key)) {
		res = -EINVAL;
		up_read(&keyring_key->sem);
		goto out;
	}
	master_key = (struct fscrypt_key *)ukp->data;
	BUILD_BUG_ON(FS_AES_128_ECB_KEY_SIZE != FS_KEY_DERIVATION_NONCE_SIZE);

	if (master_key->size != FS_AES_256_XTS_KEY_SIZE) {
		printk_once(KERN_WARNING
				"%s: key size incorrect: %d\n",
				__func__, master_key->size);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,7 @@
 	kfree(description);
 	if (IS_ERR(keyring_key))
 		return PTR_ERR(keyring_key);
+	down_read(&keyring_key->sem);
 
 	if (keyring_key->type != &key_type_logon) {
 		printk_once(KERN_WARNING
@@ -102,11 +103,9 @@
 		res = -ENOKEY;
 		goto out;
 	}
-	down_read(&keyring_key->sem);
 	ukp = user_key_payload(keyring_key);
 	if (ukp->datalen != sizeof(struct fscrypt_key)) {
 		res = -EINVAL;
-		up_read(&keyring_key->sem);
 		goto out;
 	}
 	master_key = (struct fscrypt_key *)ukp->data;
@@ -117,17 +116,11 @@
 				"%s: key size incorrect: %d\n",
 				__func__, master_key->size);
 		res = -ENOKEY;
-		up_read(&keyring_key->sem);
 		goto out;
 	}
 	res = derive_key_aes(ctx->nonce, master_key->raw, raw_key);
+out:
 	up_read(&keyring_key->sem);
-	if (res)
-		goto out;
-
-	crypt_info->ci_keyring_key = keyring_key;
-	return 0;
-out:
 	key_put(keyring_key);
 	return res;
 }
@@ -169,12 +162,11 @@
 	if (!ci)
 		return;
 
-	key_put(ci->ci_keyring_key);
 	crypto_free_skcipher(ci->ci_ctfm);
 	kmem_cache_free(fscrypt_info_cachep, ci);
 }
 
-int fscrypt_get_crypt_info(struct inode *inode)
+int fscrypt_get_encryption_info(struct inode *inode)
 {
 	struct fscrypt_info *crypt_info;
 	struct fscrypt_context ctx;
@@ -184,21 +176,15 @@
 	u8 *raw_key = NULL;
 	int res;
 
+	if (inode->i_crypt_info)
+		return 0;
+
 	res = fscrypt_initialize(inode->i_sb->s_cop->flags);
 	if (res)
 		return res;
 
 	if (!inode->i_sb->s_cop->get_context)
 		return -EOPNOTSUPP;
-retry:
-	crypt_info = ACCESS_ONCE(inode->i_crypt_info);
-	if (crypt_info) {
-		if (!crypt_info->ci_keyring_key ||
-				key_validate(crypt_info->ci_keyring_key) == 0)
-			return 0;
-		fscrypt_put_encryption_info(inode, crypt_info);
-		goto retry;
-	}
 
 	res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
 	if (res < 0) {
@@ -229,7 +215,6 @@
 	crypt_info->ci_data_mode = ctx.contents_encryption_mode;
 	crypt_info->ci_filename_mode = ctx.filenames_encryption_mode;
 	crypt_info->ci_ctfm = NULL;
-	crypt_info->ci_keyring_key = NULL;
 	memcpy(crypt_info->ci_master_key, ctx.master_key_descriptor,
 				sizeof(crypt_info->ci_master_key));
 
@@ -273,14 +258,8 @@
 	if (res)
 		goto out;
 
-	kzfree(raw_key);
-	raw_key = NULL;
-	if (cmpxchg(&inode->i_crypt_info, NULL, crypt_info) != NULL) {
-		put_crypt_info(crypt_info);
-		goto retry;
-	}
-	return 0;
-
+	if (cmpxchg(&inode->i_crypt_info, NULL, crypt_info) == NULL)
+		crypt_info = NULL;
 out:
 	if (res == -ENOKEY)
 		res = 0;
@@ -288,6 +267,7 @@
 	kzfree(raw_key);
 	return res;
 }
+EXPORT_SYMBOL(fscrypt_get_encryption_info);
 
 void fscrypt_put_encryption_info(struct inode *inode, struct fscrypt_info *ci)
 {
@@ -305,17 +285,3 @@
 	put_crypt_info(ci);
 }
 EXPORT_SYMBOL(fscrypt_put_encryption_info);
-
-int fscrypt_get_encryption_info(struct inode *inode)
-{
-	struct fscrypt_info *ci = inode->i_crypt_info;
-
-	if (!ci ||
-		(ci->ci_keyring_key &&
-		 (ci->ci_keyring_key->flags & ((1 << KEY_FLAG_INVALIDATED) |
-					       (1 << KEY_FLAG_REVOKED) |
-					       (1 << KEY_FLAG_DEAD)))))
-		return fscrypt_get_crypt_info(inode);
-	return 0;
-}
-EXPORT_SYMBOL(fscrypt_get_encryption_info);
```
