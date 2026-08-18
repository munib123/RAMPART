# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3460_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3460_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 158-198 of the vulnerable file.

void ecryptfs_put_lower_file(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;

	inode_info = ecryptfs_inode_to_private(inode);
	if (atomic_dec_and_mutex_lock(&inode_info->lower_file_count,
				      &inode_info->lower_file_mutex)) {
		fput(inode_info->lower_file);
		inode_info->lower_file = NULL;
		mutex_unlock(&inode_info->lower_file_mutex);
	}
}

enum { ecryptfs_opt_sig, ecryptfs_opt_ecryptfs_sig,
       ecryptfs_opt_cipher, ecryptfs_opt_ecryptfs_cipher,
       ecryptfs_opt_ecryptfs_key_bytes,
       ecryptfs_opt_passthrough, ecryptfs_opt_xattr_metadata,
       ecryptfs_opt_encrypted_view, ecryptfs_opt_fnek_sig,
       ecryptfs_opt_fn_cipher, ecryptfs_opt_fn_cipher_key_bytes,
       ecryptfs_opt_unlink_sigs, ecryptfs_opt_mount_auth_tok_only,
       ecryptfs_opt_err };

static const match_table_t tokens = {
	{ecryptfs_opt_sig, "sig=%s"},
	{ecryptfs_opt_ecryptfs_sig, "ecryptfs_sig=%s"},
	{ecryptfs_opt_cipher, "cipher=%s"},
	{ecryptfs_opt_ecryptfs_cipher, "ecryptfs_cipher=%s"},
	{ecryptfs_opt_ecryptfs_key_bytes, "ecryptfs_key_bytes=%u"},
	{ecryptfs_opt_passthrough, "ecryptfs_passthrough"},
	{ecryptfs_opt_xattr_metadata, "ecryptfs_xattr_metadata"},
	{ecryptfs_opt_encrypted_view, "ecryptfs_encrypted_view"},
	{ecryptfs_opt_fnek_sig, "ecryptfs_fnek_sig=%s"},
	{ecryptfs_opt_fn_cipher, "ecryptfs_fn_cipher=%s"},
	{ecryptfs_opt_fn_cipher_key_bytes, "ecryptfs_fn_key_bytes=%u"},
	{ecryptfs_opt_unlink_sigs, "ecryptfs_unlink_sigs"},
	{ecryptfs_opt_mount_auth_tok_only, "ecryptfs_mount_auth_tok_only"},
	{ecryptfs_opt_err, NULL}
};

static int ecryptfs_init_global_auth_toks(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -175,6 +175,7 @@
        ecryptfs_opt_encrypted_view, ecryptfs_opt_fnek_sig,
        ecryptfs_opt_fn_cipher, ecryptfs_opt_fn_cipher_key_bytes,
        ecryptfs_opt_unlink_sigs, ecryptfs_opt_mount_auth_tok_only,
+       ecryptfs_opt_check_dev_ruid,
        ecryptfs_opt_err };
 
 static const match_table_t tokens = {
@@ -191,6 +192,7 @@
 	{ecryptfs_opt_fn_cipher_key_bytes, "ecryptfs_fn_key_bytes=%u"},
 	{ecryptfs_opt_unlink_sigs, "ecryptfs_unlink_sigs"},
 	{ecryptfs_opt_mount_auth_tok_only, "ecryptfs_mount_auth_tok_only"},
+	{ecryptfs_opt_check_dev_ruid, "ecryptfs_check_dev_ruid"},
 	{ecryptfs_opt_err, NULL}
 };
 
@@ -236,6 +238,7 @@
  * ecryptfs_parse_options
  * @sb: The ecryptfs super block
  * @options: The options passed to the kernel
+ * @check_ruid: set to 1 if device uid should be checked against the ruid
  *
  * Parse mount options:
  * debug=N 	   - ecryptfs_verbosity level for debug output
@@ -251,7 +254,8 @@
  *
  * Returns zero on success; non-zero on error
  */
-static int ecryptfs_parse_options(struct ecryptfs_sb_info *sbi, char *options)
+static int ecryptfs_parse_options(struct ecryptfs_sb_info *sbi, char *options,
+				  uid_t *check_ruid)
 {
 	char *p;
 	int rc = 0;
@@ -276,6 +280,8 @@
 	char *cipher_key_bytes_src;
 	char *fn_cipher_key_bytes_src;
 
+	*check_ruid = 0;
+
 	if (!options) {
 		rc = -EINVAL;
 		goto out;
@@ -379,6 +385,9 @@
 		case ecryptfs_opt_mount_auth_tok_only:
 			mount_crypt_stat->flags |=
 				ECRYPTFS_GLOBAL_MOUNT_AUTH_TOK_ONLY;
+			break;
+		case ecryptfs_opt_check_dev_ruid:
+			*check_ruid = 1;
 			break;
 		case ecryptfs_opt_err:
 		default:
@@ -475,6 +484,7 @@
 	const char *err = "Getting sb failed";
 	struct inode *inode;
 	struct path path;
+	uid_t check_ruid;
 	int rc;
 
 	sbi = kmem_cache_zalloc(ecryptfs_sb_info_cache, GFP_KERNEL);
@@ -483,7 +493,7 @@
 		goto out;
 	}
 
-	rc = ecryptfs_parse_options(sbi, raw_data);
+	rc = ecryptfs_parse_options(sbi, raw_data, &check_ruid);
 	if (rc) {
 		err = "Error parsing options";
 		goto out;
@@ -521,6 +531,15 @@
 			"known incompatibilities\n");
 		goto out_free;
 	}
+
+	if (check_ruid && path.dentry->d_inode->i_uid != current_uid()) {
+		rc = -EPERM;
+		printk(KERN_ERR "Mount of device (uid: %d) not owned by "
+		       "requested user (uid: %d)\n",
+		       path.dentry->d_inode->i_uid, current_uid());
+		goto out_free;
+	}
+
 	ecryptfs_set_superblock_lower(s, path.dentry->d_sb);
 	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
 	s->s_blocksize = path.dentry->d_sb->s_blocksize;
```
