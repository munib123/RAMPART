# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 4858_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4858_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 78-118 of the vulnerable file.

			"%s: Invalid filenames encryption mode %d\n", __func__,
			policy->filenames_encryption_mode);
		return -EINVAL;
	}

	if (policy->flags & ~FS_POLICY_FLAGS_VALID)
		return -EINVAL;

	ctx.contents_encryption_mode = policy->contents_encryption_mode;
	ctx.filenames_encryption_mode = policy->filenames_encryption_mode;
	ctx.flags = policy->flags;
	BUILD_BUG_ON(sizeof(ctx.nonce) != FS_KEY_DERIVATION_NONCE_SIZE);
	get_random_bytes(ctx.nonce, FS_KEY_DERIVATION_NONCE_SIZE);

	return inode->i_sb->s_cop->set_context(inode, &ctx, sizeof(ctx), NULL);
}

int fscrypt_process_policy(struct inode *inode,
				const struct fscrypt_policy *policy)
{
	if (policy->version != 0)
		return -EINVAL;

	if (!inode_has_encryption_context(inode)) {
		if (!inode->i_sb->s_cop->empty_dir)
			return -EOPNOTSUPP;
		if (!inode->i_sb->s_cop->empty_dir(inode))
			return -ENOTEMPTY;
		return create_encryption_context_from_policy(inode, policy);
	}

	if (is_encryption_context_consistent_with_policy(inode, policy))
		return 0;

	printk(KERN_WARNING "%s: Policy inconsistent with encryption context\n",
	       __func__);
	return -EINVAL;
}
EXPORT_SYMBOL(fscrypt_process_policy);

int fscrypt_get_policy(struct inode *inode, struct fscrypt_policy *policy)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -95,6 +95,9 @@
 int fscrypt_process_policy(struct inode *inode,
 				const struct fscrypt_policy *policy)
 {
+	if (!inode_owner_or_capable(inode))
+		return -EACCES;
+
 	if (policy->version != 0)
 		return -EINVAL;
 
```
