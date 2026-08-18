# CrossVul Fix Pair: Improper Validation of Array Index in c
**Pair ID:** 1431_0
**Vulnerability Class:** Improper Validation of Array Index
**CWE:** CWE-129
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1431_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Array Index - The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position withi...

## Vulnerable Code
```c
Lines 88-128 of the vulnerable file.

		s[3] = ~s[3];
		s[4] = ~s[4];
		s[5] = ~0;
		size = 12;
	} else {
		memcpy(&s[0], &ctx->from, 4);
		memcpy(&s[4], &ctx->to, 4);
		s[0] = ~s[0];
		s[1] = ~s[1];
		s[2] = ~s[2];
		s[3] = ~s[3];
		size = 8;
	}
	*ctx->check = csum_fold(csum_partial(s, size,
					     ~csum_unfold(*ctx->check)));
}

int snmp_version(void *context, size_t hdrlen, unsigned char tag,
		 const void *data, size_t datalen)
{
	if (*(unsigned char *)data > 1)
		return -ENOTSUPP;
	return 1;
}

int snmp_helper(void *context, size_t hdrlen, unsigned char tag,
		const void *data, size_t datalen)
{
	struct snmp_ctx *ctx = (struct snmp_ctx *)context;
	__be32 *pdata = (__be32 *)data;

	if (*pdata == ctx->from) {
		pr_debug("%s: %pI4 to %pI4\n", __func__,
			 (void *)&ctx->from, (void *)&ctx->to);

		if (*ctx->check)
			fast_csum(ctx, (unsigned char *)data - ctx->begin);
		*pdata = ctx->to;
	}

	return 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,6 +105,8 @@
 int snmp_version(void *context, size_t hdrlen, unsigned char tag,
 		 const void *data, size_t datalen)
 {
+	if (datalen != 1)
+		return -EINVAL;
 	if (*(unsigned char *)data > 1)
 		return -ENOTSUPP;
 	return 1;
@@ -114,8 +116,11 @@
 		const void *data, size_t datalen)
 {
 	struct snmp_ctx *ctx = (struct snmp_ctx *)context;
-	__be32 *pdata = (__be32 *)data;
-
+	__be32 *pdata;
+
+	if (datalen != 4)
+		return -EINVAL;
+	pdata = (__be32 *)data;
 	if (*pdata == ctx->from) {
 		pr_debug("%s: %pI4 to %pI4\n", __func__,
 			 (void *)&ctx->from, (void *)&ctx->to);
```
