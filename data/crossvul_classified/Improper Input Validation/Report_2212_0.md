# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2212_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2212_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1583-1624 of the vulnerable file.

			      strlen(pool->swork.prev_hash);
	pool->swork.header_len = pool->merkle_offset +
	/* merkle_hash */	 32 +
				 strlen(pool->swork.ntime) +
				 strlen(pool->swork.nbit) +
	/* nonce */		 8 +
	/* workpadding */	 96;
	pool->merkle_offset /= 2;
	pool->swork.header_len = pool->swork.header_len * 2 + 1;
	align_len(&pool->swork.header_len);
	header = (char *)alloca(pool->swork.header_len);
	snprintf(header, pool->swork.header_len,
		"%s%s%s%s%s%s%s",
		pool->swork.bbversion,
		pool->swork.prev_hash,
		blank_merkel,
		pool->swork.ntime,
		pool->swork.nbit,
		"00000000", /* nonce */
		workpadding);
	if (unlikely(!hex2bin(pool->header_bin, header, 128)))
		quit(1, "Failed to convert header to header_bin in parse_notify");

	cb1 = (unsigned char *)calloc(cb1_len, 1);
	if (unlikely(!cb1))
		quithere(1, "Failed to calloc cb1 in parse_notify");
	hex2bin(cb1, coinbase1, cb1_len);
	cb2 = (unsigned char *)calloc(cb2_len, 1);
	if (unlikely(!cb2))
		quithere(1, "Failed to calloc cb2 in parse_notify");
	hex2bin(cb2, coinbase2, cb2_len);
	free(pool->coinbase);
	align_len(&alloc_len);
	pool->coinbase = (unsigned char *)calloc(alloc_len, 1);
	if (unlikely(!pool->coinbase))
		quit(1, "Failed to calloc pool coinbase in parse_notify");
	memcpy(pool->coinbase, cb1, cb1_len);
	memcpy(pool->coinbase + cb1_len, pool->nonce1bin, pool->n1_len);
	memcpy(pool->coinbase + cb1_len + pool->n1_len + pool->n2size, cb2, cb2_len);
	cg_wunlock(&pool->data_lock);

	if (opt_protocol) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1600,17 +1600,23 @@
 		pool->swork.nbit,
 		"00000000", /* nonce */
 		workpadding);
-	if (unlikely(!hex2bin(pool->header_bin, header, 128)))
-		quit(1, "Failed to convert header to header_bin in parse_notify");
+	if (unlikely(!hex2bin(pool->header_bin, header, 128))) {
+		applog(LOG_WARNING, "%s: Failed to convert header to header_bin, got %s", __func__, header);
+		pool_failed(pool);
+		// TODO: memory leaks? goto out, clean up there?
+		return false;
+	}
 
 	cb1 = (unsigned char *)calloc(cb1_len, 1);
 	if (unlikely(!cb1))
 		quithere(1, "Failed to calloc cb1 in parse_notify");
 	hex2bin(cb1, coinbase1, cb1_len);
+
 	cb2 = (unsigned char *)calloc(cb2_len, 1);
 	if (unlikely(!cb2))
 		quithere(1, "Failed to calloc cb2 in parse_notify");
 	hex2bin(cb2, coinbase2, cb2_len);
+
 	free(pool->coinbase);
 	align_len(&alloc_len);
 	pool->coinbase = (unsigned char *)calloc(alloc_len, 1);
@@ -1618,6 +1624,7 @@
 		quit(1, "Failed to calloc pool coinbase in parse_notify");
 	memcpy(pool->coinbase, cb1, cb1_len);
 	memcpy(pool->coinbase + cb1_len, pool->nonce1bin, pool->n1_len);
+	// NOTE: gap for nonce2, filled at work generation time
 	memcpy(pool->coinbase + cb1_len + pool->n1_len + pool->n2size, cb2, cb2_len);
 	cg_wunlock(&pool->data_lock);
 
```
