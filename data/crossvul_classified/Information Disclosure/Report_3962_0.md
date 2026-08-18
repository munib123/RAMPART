# CrossVul Fix Pair: Observable Discrepancy in c
**Pair ID:** 3962_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-203
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3962_0`)

## Vulnerability Information & PoC

## Description
Observable Discrepancy - Discrepancies can take many forms, and variations may be detectable in timing, control flow, communications such as replies or requests, or general behavior.

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.

	unsigned int fixed_length;
	const unsigned int *cmac;
	int rc = -1;

	/* Init keys */
	init_keys(&key_size, cipher_key, cmac_key, iv);

	/* Init periph */
	at91_aes_init();

	/* Check signature if required */
	if (is_signed) {
		/* Compute the CMAC */
		if (at91_aes_cmac(data_length, data, computed_cmac,
				  key_size, cmac_key))
			goto exit;

		/* Check the CMAC */
		fixed_length = at91_aes_roundup(data_length);
		cmac = (const unsigned int *)((char *)data + fixed_length);
		if (memcmp(cmac, computed_cmac, AT91_AES_BLOCK_SIZE_BYTE))
			goto exit;
	}

	/* Decrypt the whole file */
	if (at91_aes_cbc(data_length, data, data, 0,
			 key_size, cipher_key, iv))
		goto exit;

	rc = 0;
exit:
	/* Reset periph */
	at91_aes_cleanup();

	/* Reset keys */
	memset(cmac_key, 0, sizeof(cmac_key));
	memset(cipher_key, 0, sizeof(cipher_key));
	memset(iv, 0, sizeof(iv));

	return rc;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,7 +103,7 @@
 		/* Check the CMAC */
 		fixed_length = at91_aes_roundup(data_length);
 		cmac = (const unsigned int *)((char *)data + fixed_length);
-		if (memcmp(cmac, computed_cmac, AT91_AES_BLOCK_SIZE_BYTE))
+		if (!consttime_memequal(cmac, computed_cmac, AT91_AES_BLOCK_SIZE_BYTE))
 			goto exit;
 	}
 
```
