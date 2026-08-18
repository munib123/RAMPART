# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 42-83 of the vulnerable file.

	kidlen = strlen(kid);
	if (idlen > kidlen)
		return 0;

	kid += kidlen - idlen;
	if (strcasecmp(id, kid) != 0)
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(asymmetric_keyid_match);

/*
 * Match asymmetric keys on (part of) their name
 * We have some shorthand methods for matching keys.  We allow:
 *
 *	"<desc>"	- request a key by description
 *	"id:<id>"	- request a key matching the ID
 *	"<subtype>:<id>" - request a key of a subtype
 */
static int asymmetric_key_match(const struct key *key,
				const struct key_match_data *match_data)
{
	const struct asymmetric_key_subtype *subtype = asymmetric_key_subtype(key);
	const char *description = match_data->raw_data;
	const char *spec = description;
	const char *id;
	ptrdiff_t speclen;

	if (!subtype || !spec || !*spec)
		return 0;

	/* See if the full key description matches as is */
	if (key->description && strcmp(key->description, description) == 0)
		return 1;

	/* All tests from here on break the criterion description into a
	 * specifier, a colon and then an identifier.
	 */
	id = strchr(spec, ':');
	if (!id)
		return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,8 +59,8 @@
  *	"id:<id>"	- request a key matching the ID
  *	"<subtype>:<id>" - request a key of a subtype
  */
-static int asymmetric_key_match(const struct key *key,
-				const struct key_match_data *match_data)
+static int asymmetric_key_cmp(const struct key *key,
+			      const struct key_match_data *match_data)
 {
 	const struct asymmetric_key_subtype *subtype = asymmetric_key_subtype(key);
 	const char *description = match_data->raw_data;
@@ -110,6 +110,7 @@
 static int asymmetric_key_match_preparse(struct key_match_data *match_data)
 {
 	match_data->lookup_type = KEYRING_SEARCH_LOOKUP_ITERATE;
+	match_data->cmp = asymmetric_key_cmp;
 	return 0;
 }
 
@@ -224,7 +225,6 @@
 	.free_preparse	= asymmetric_key_free_preparse,
 	.instantiate	= generic_key_instantiate,
 	.match_preparse	= asymmetric_key_match_preparse,
-	.match		= asymmetric_key_match,
 	.match_free	= asymmetric_key_match_free,
 	.destroy	= asymmetric_key_destroy,
 	.describe	= asymmetric_key_describe,
```
