# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1787_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1787_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 990-1030 of the vulnerable file.

		rcu_assign_keypointer(key, payload);
	else
		kfree(payload);
	return ret;
}

static void trusted_rcu_free(struct rcu_head *rcu)
{
	struct trusted_key_payload *p;

	p = container_of(rcu, struct trusted_key_payload, rcu);
	memset(p->key, 0, p->key_len);
	kfree(p);
}

/*
 * trusted_update - reseal an existing key with new PCR values
 */
static int trusted_update(struct key *key, struct key_preparsed_payload *prep)
{
	struct trusted_key_payload *p = key->payload.data[0];
	struct trusted_key_payload *new_p;
	struct trusted_key_options *new_o;
	size_t datalen = prep->datalen;
	char *datablob;
	int ret = 0;

	if (!p->migratable)
		return -EPERM;
	if (datalen <= 0 || datalen > 32767 || !prep->data)
		return -EINVAL;

	datablob = kmalloc(datalen + 1, GFP_KERNEL);
	if (!datablob)
		return -ENOMEM;
	new_o = trusted_options_alloc();
	if (!new_o) {
		ret = -ENOMEM;
		goto out;
	}
	new_p = trusted_payload_alloc(key);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1007,13 +1007,16 @@
  */
 static int trusted_update(struct key *key, struct key_preparsed_payload *prep)
 {
-	struct trusted_key_payload *p = key->payload.data[0];
+	struct trusted_key_payload *p;
 	struct trusted_key_payload *new_p;
 	struct trusted_key_options *new_o;
 	size_t datalen = prep->datalen;
 	char *datablob;
 	int ret = 0;
 
+	if (test_bit(KEY_FLAG_NEGATIVE, &key->flags))
+		return -ENOKEY;
+	p = key->payload.data[0];
 	if (!p->migratable)
 		return -EPERM;
 	if (datalen <= 0 || datalen > 32767 || !prep->data)
```
