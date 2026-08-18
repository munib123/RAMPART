# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2080_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2080_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1214-1254 of the vulnerable file.

	if ((p - scontext) < scontext_len)
		goto out;

	/* Check the validity of the new context. */
	if (!policydb_context_isvalid(pol, ctx))
		goto out;
	rc = 0;
out:
	if (rc)
		context_destroy(ctx);
	return rc;
}

static int security_context_to_sid_core(const char *scontext, u32 scontext_len,
					u32 *sid, u32 def_sid, gfp_t gfp_flags,
					int force)
{
	char *scontext2, *str = NULL;
	struct context context;
	int rc = 0;

	if (!ss_initialized) {
		int i;

		for (i = 1; i < SECINITSID_NUM; i++) {
			if (!strcmp(initial_sid_to_string[i], scontext)) {
				*sid = i;
				return 0;
			}
		}
		*sid = SECINITSID_KERNEL;
		return 0;
	}
	*sid = SECSID_NULL;

	/* Copy the string so that we can modify the copy as we parse it. */
	scontext2 = kmalloc(scontext_len + 1, gfp_flags);
	if (!scontext2)
		return -ENOMEM;
	memcpy(scontext2, scontext, scontext_len);
	scontext2[scontext_len] = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1232,6 +1232,10 @@
 	struct context context;
 	int rc = 0;
 
+	/* An empty security context is never valid. */
+	if (!scontext_len)
+		return -EINVAL;
+
 	if (!ss_initialized) {
 		int i;
 
```
