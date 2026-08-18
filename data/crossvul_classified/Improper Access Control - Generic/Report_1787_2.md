# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1787_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1787_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 103-143 of the vulnerable file.

	ret = -EINVAL;
	if (datalen <= 0 || datalen > 32767 || !prep->data)
		goto error;

	/* construct a replacement payload */
	ret = -ENOMEM;
	upayload = kmalloc(sizeof(*upayload) + datalen, GFP_KERNEL);
	if (!upayload)
		goto error;

	upayload->datalen = datalen;
	memcpy(upayload->data, prep->data, datalen);

	/* check the quota and attach the new data */
	zap = upayload;

	ret = key_payload_reserve(key, datalen);

	if (ret == 0) {
		/* attach the new data, displacing the old */
		zap = key->payload.data[0];
		rcu_assign_keypointer(key, upayload);
		key->expiry = 0;
	}

	if (zap)
		kfree_rcu(zap, rcu);

error:
	return ret;
}

EXPORT_SYMBOL_GPL(user_update);

/*
 * dispose of the links from a revoked keyring
 * - called with the key sem write-locked
 */
void user_revoke(struct key *key)
{
	struct user_key_payload *upayload = key->payload.data[0];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,7 +120,10 @@
 
 	if (ret == 0) {
 		/* attach the new data, displacing the old */
-		zap = key->payload.data[0];
+		if (!test_bit(KEY_FLAG_NEGATIVE, &key->flags))
+			zap = key->payload.data[0];
+		else
+			zap = NULL;
 		rcu_assign_keypointer(key, upayload);
 		key->expiry = 0;
 	}
```
