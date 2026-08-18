# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_8
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_8`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 159-201 of the vulnerable file.

	kleave(" = 0");
	return 0;
}

/*
 * Clean up the preparse data
 */
static void dns_resolver_free_preparse(struct key_preparsed_payload *prep)
{
	pr_devel("==>%s()\n", __func__);

	kfree(prep->payload[0]);
}

/*
 * The description is of the form "[<type>:]<domain_name>"
 *
 * The domain name may be a simple name or an absolute domain name (which
 * should end with a period).  The domain name is case-independent.
 */
static int
dns_resolver_match(const struct key *key,
		   const struct key_match_data *match_data)
{
	int slen, dlen, ret = 0;
	const char *src = key->description, *dsp = match_data->raw_data;

	kenter("%s,%s", src, dsp);

	if (!src || !dsp)
		goto no_match;

	if (strcasecmp(src, dsp) == 0)
		goto matched;

	slen = strlen(src);
	dlen = strlen(dsp);
	if (slen <= 0 || dlen <= 0)
		goto no_match;
	if (src[slen - 1] == '.')
		slen--;
	if (dsp[dlen - 1] == '.')
		dlen--;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,9 +176,8 @@
  * The domain name may be a simple name or an absolute domain name (which
  * should end with a period).  The domain name is case-independent.
  */
-static int
-dns_resolver_match(const struct key *key,
-		   const struct key_match_data *match_data)
+static int dns_resolver_cmp(const struct key *key,
+			    const struct key_match_data *match_data)
 {
 	int slen, dlen, ret = 0;
 	const char *src = key->description, *dsp = match_data->raw_data;
@@ -210,6 +209,16 @@
 }
 
 /*
+ * Preparse the match criterion.
+ */
+static int dns_resolver_match_preparse(struct key_match_data *match_data)
+{
+	match_data->lookup_type = KEYRING_SEARCH_LOOKUP_ITERATE;
+	match_data->cmp = dns_resolver_cmp;
+	return 0;
+}
+
+/*
  * Describe a DNS key
  */
 static void dns_resolver_describe(const struct key *key, struct seq_file *m)
@@ -243,7 +252,7 @@
 	.preparse	= dns_resolver_preparse,
 	.free_preparse	= dns_resolver_free_preparse,
 	.instantiate	= generic_key_instantiate,
-	.match		= dns_resolver_match,
+	.match_preparse	= dns_resolver_match_preparse,
 	.revoke		= user_revoke,
 	.destroy	= user_destroy,
 	.describe	= dns_resolver_describe,
```
