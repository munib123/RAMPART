# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3256_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3256_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 333-373 of the vulnerable file.

	 * a disk-space name
	 */
	return -ENOKEY;
}
EXPORT_SYMBOL(fscrypt_fname_usr_to_disk);

int fscrypt_setup_filename(struct inode *dir, const struct qstr *iname,
			      int lookup, struct fscrypt_name *fname)
{
	int ret = 0, bigname = 0;

	memset(fname, 0, sizeof(struct fscrypt_name));
	fname->usr_fname = iname;

	if (!dir->i_sb->s_cop->is_encrypted(dir) ||
				fscrypt_is_dot_dotdot(iname)) {
		fname->disk_name.name = (unsigned char *)iname->name;
		fname->disk_name.len = iname->len;
		return 0;
	}
	ret = fscrypt_get_crypt_info(dir);
	if (ret && ret != -EOPNOTSUPP)
		return ret;

	if (dir->i_crypt_info) {
		ret = fscrypt_fname_alloc_buffer(dir, iname->len,
							&fname->crypto_buf);
		if (ret)
			return ret;
		ret = fname_encrypt(dir, iname, &fname->crypto_buf);
		if (ret)
			goto errout;
		fname->disk_name.name = fname->crypto_buf.name;
		fname->disk_name.len = fname->crypto_buf.len;
		return 0;
	}
	if (!lookup)
		return -ENOKEY;

	/*
	 * We don't have the key and we are doing a lookup; decode the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -350,7 +350,7 @@
 		fname->disk_name.len = iname->len;
 		return 0;
 	}
-	ret = fscrypt_get_crypt_info(dir);
+	ret = fscrypt_get_encryption_info(dir);
 	if (ret && ret != -EOPNOTSUPP)
 		return ret;
 
```
