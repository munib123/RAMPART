# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1787_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1787_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 828-868 of the vulnerable file.


/*
 * encrypted_update - update the master key description
 *
 * Change the master key description for an existing encrypted key.
 * The next read will return an encrypted datablob using the new
 * master key description.
 *
 * On success, return 0. Otherwise return errno.
 */
static int encrypted_update(struct key *key, struct key_preparsed_payload *prep)
{
	struct encrypted_key_payload *epayload = key->payload.data[0];
	struct encrypted_key_payload *new_epayload;
	char *buf;
	char *new_master_desc = NULL;
	const char *format = NULL;
	size_t datalen = prep->datalen;
	int ret = 0;

	if (datalen <= 0 || datalen > 32767 || !prep->data)
		return -EINVAL;

	buf = kmalloc(datalen + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf[datalen] = 0;
	memcpy(buf, prep->data, datalen);
	ret = datablob_parse(buf, &format, &new_master_desc, NULL, NULL);
	if (ret < 0)
		goto out;

	ret = valid_master_desc(new_master_desc, epayload->master_desc);
	if (ret < 0)
		goto out;

	new_epayload = encrypted_key_alloc(key, epayload->format,
					   new_master_desc, epayload->datalen);
	if (IS_ERR(new_epayload)) {
		ret = PTR_ERR(new_epayload);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -845,6 +845,8 @@
 	size_t datalen = prep->datalen;
 	int ret = 0;
 
+	if (test_bit(KEY_FLAG_NEGATIVE, &key->flags))
+		return -ENOKEY;
 	if (datalen <= 0 || datalen > 32767 || !prep->data)
 		return -EINVAL;
 
```
