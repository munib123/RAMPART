# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3060_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3060_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 45-85 of the vulnerable file.

	key->payload.data = payload;
	ret = 0;

error:
	return ret;
}

static void
cifs_spnego_key_destroy(struct key *key)
{
	kfree(key->payload.data);
}


/*
 * keytype for CIFS spnego keys
 */
struct key_type cifs_spnego_key_type = {
	.name		= "cifs.spnego",
	.instantiate	= cifs_spnego_key_instantiate,
	.match		= user_match,
	.destroy	= cifs_spnego_key_destroy,
	.describe	= user_describe,
};

/* length of longest version string e.g.  strlen("ver=0xFF") */
#define MAX_VER_STR_LEN		8

/* length of longest security mechanism name, eg in future could have
 * strlen(";sec=ntlmsspi") */
#define MAX_MECH_STR_LEN	13

/* strlen of "host=" */
#define HOST_KEY_LEN		5

/* strlen of ";ip4=" or ";ip6=" */
#define IP_KEY_LEN		5

/* strlen of ";uid=0x" */
#define UID_KEY_LEN		7

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,7 +62,6 @@
 struct key_type cifs_spnego_key_type = {
 	.name		= "cifs.spnego",
 	.instantiate	= cifs_spnego_key_instantiate,
-	.match		= user_match,
 	.destroy	= cifs_spnego_key_destroy,
 	.describe	= user_describe,
 };
```
