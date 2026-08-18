# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2891_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2891_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 207-247 of the vulnerable file.

	kleave(" = %d", ret);
	return ret;
}

/*
 * Preparse the match criterion.
 */
static int dns_resolver_match_preparse(struct key_match_data *match_data)
{
	match_data->lookup_type = KEYRING_SEARCH_LOOKUP_ITERATE;
	match_data->cmp = dns_resolver_cmp;
	return 0;
}

/*
 * Describe a DNS key
 */
static void dns_resolver_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);
	if (key_is_instantiated(key)) {
		int err = PTR_ERR(key->payload.data[dns_key_error]);

		if (err)
			seq_printf(m, ": %d", err);
		else
			seq_printf(m, ": %u", key->datalen);
	}
}

/*
 * read the DNS data
 * - the key's semaphore is read-locked
 */
static long dns_resolver_read(const struct key *key,
			      char __user *buffer, size_t buflen)
{
	int err = PTR_ERR(key->payload.data[dns_key_error]);

	if (err)
		return err;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -224,7 +224,7 @@
 static void dns_resolver_describe(const struct key *key, struct seq_file *m)
 {
 	seq_puts(m, key->description);
-	if (key_is_instantiated(key)) {
+	if (key_is_positive(key)) {
 		int err = PTR_ERR(key->payload.data[dns_key_error]);
 
 		if (err)
```
