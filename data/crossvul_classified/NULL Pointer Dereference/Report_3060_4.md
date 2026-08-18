# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_4
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_4`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 160-200 of the vulnerable file.

	if (memchr(name, '@', namelen) != NULL || namelen >= sizeof(buf))
		return 0;
	memcpy(buf, name, namelen);
	buf[namelen] = '\0';
	if (kstrtoul(buf, 0, &val) != 0)
		return 0;
	*res = val;
	return 1;
}

static int nfs_map_numeric_to_string(__u32 id, char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "%u", id);
}

static struct key_type key_type_id_resolver = {
	.name		= "id_resolver",
	.preparse	= user_preparse,
	.free_preparse	= user_free_preparse,
	.instantiate	= generic_key_instantiate,
	.match		= user_match,
	.revoke		= user_revoke,
	.destroy	= user_destroy,
	.describe	= user_describe,
	.read		= user_read,
};

static int nfs_idmap_init_keyring(void)
{
	struct cred *cred;
	struct key *keyring;
	int ret = 0;

	printk(KERN_NOTICE "NFS: Registering the %s key type\n",
		key_type_id_resolver.name);

	cred = prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	keyring = keyring_alloc(".id_resolver",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,7 +177,6 @@
 	.preparse	= user_preparse,
 	.free_preparse	= user_free_preparse,
 	.instantiate	= generic_key_instantiate,
-	.match		= user_match,
 	.revoke		= user_revoke,
 	.destroy	= user_destroy,
 	.describe	= user_describe,
@@ -401,7 +400,6 @@
 	.preparse	= user_preparse,
 	.free_preparse	= user_free_preparse,
 	.instantiate	= generic_key_instantiate,
-	.match		= user_match,
 	.revoke		= user_revoke,
 	.destroy	= user_destroy,
 	.describe	= user_describe,
```
