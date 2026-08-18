# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4735_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4735_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 113-153 of the vulnerable file.

 * Parse the common sections of a ADD message and fill in the related values
 * in @doi_def.  Returns zero on success, negative values on failure.
 *
 */
static int netlbl_cipsov4_add_common(struct genl_info *info,
				     struct cipso_v4_doi *doi_def)
{
	struct nlattr *nla;
	int nla_rem;
	u32 iter = 0;

	doi_def->doi = nla_get_u32(info->attrs[NLBL_CIPSOV4_A_DOI]);

	if (nla_validate_nested(info->attrs[NLBL_CIPSOV4_A_TAGLST],
				NLBL_CIPSOV4_A_MAX,
				netlbl_cipsov4_genl_policy) != 0)
		return -EINVAL;

	nla_for_each_nested(nla, info->attrs[NLBL_CIPSOV4_A_TAGLST], nla_rem)
		if (nla->nla_type == NLBL_CIPSOV4_A_TAG) {
			if (iter > CIPSO_V4_TAG_MAXCNT)
				return -EINVAL;
			doi_def->tags[iter++] = nla_get_u8(nla);
		}
	if (iter < CIPSO_V4_TAG_MAXCNT)
		doi_def->tags[iter] = CIPSO_V4_TAG_INVALID;

	return 0;
}

/*
 * NetLabel Command Handlers
 */

/**
 * netlbl_cipsov4_add_std - Adds a CIPSO V4 DOI definition
 * @info: the Generic NETLINK info block
 *
 * Description:
 * Create a new CIPSO_V4_MAP_STD DOI definition based on the given ADD message
 * and add it to the CIPSO V4 engine.  Return zero on success and non-zero on
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,12 +130,12 @@
 
 	nla_for_each_nested(nla, info->attrs[NLBL_CIPSOV4_A_TAGLST], nla_rem)
 		if (nla->nla_type == NLBL_CIPSOV4_A_TAG) {
-			if (iter > CIPSO_V4_TAG_MAXCNT)
+			if (iter >= CIPSO_V4_TAG_MAXCNT)
 				return -EINVAL;
 			doi_def->tags[iter++] = nla_get_u8(nla);
 		}
-	if (iter < CIPSO_V4_TAG_MAXCNT)
-		doi_def->tags[iter] = CIPSO_V4_TAG_INVALID;
+	while (iter < CIPSO_V4_TAG_MAXCNT)
+		doi_def->tags[iter++] = CIPSO_V4_TAG_INVALID;
 
 	return 0;
 }
```
