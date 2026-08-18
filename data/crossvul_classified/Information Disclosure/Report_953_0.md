# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 953_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `953_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 175-215 of the vulnerable file.

	}

	if (!EC_GROUP_get_order(session->group, session->order, NULL)) {
		DEBUG("unable to get order for curve");
		goto fail;
	}

	if (!EC_GROUP_get_cofactor(session->group, cofactor, NULL)) {
		DEBUG("unable to get cofactor for curve");
		goto fail;
	}

	primebitlen = BN_num_bits(session->prime);
	primebytelen = BN_num_bytes(session->prime);
	if ((prfbuf = talloc_zero_array(session, uint8_t, primebytelen)) == NULL) {
		DEBUG("unable to alloc space for prf buffer");
		goto fail;
	}
	ctr = 0;
	while (1) {
		if (ctr > 10) {
			DEBUG("unable to find random point on curve for group %d, something's fishy", grp_num);
			goto fail;
		}
		ctr++;

		/*
		 * compute counter-mode password value and stretch to prime
		 *    pwd-seed = H(token | peer-id | server-id | password |
		 *		   counter)
		 */
		H_Init(ctx);
		H_Update(ctx, (uint8_t *)token, sizeof(*token));
		H_Update(ctx, (uint8_t const *)id_peer, id_peer_len);
		H_Update(ctx, (uint8_t const *)id_server, id_server_len);
		H_Update(ctx, (uint8_t const *)password, password_len);
		H_Update(ctx, (uint8_t *)&ctr, sizeof(ctr));
		H_Final(ctx, pwe_digest);

		BN_bin2bn(pwe_digest, SHA256_DIGEST_LENGTH, rnd);
		if (eap_pwd_kdf(pwe_digest, SHA256_DIGEST_LENGTH, "EAP-pwd Hunting And Pecking",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,7 +192,7 @@
 	}
 	ctr = 0;
 	while (1) {
-		if (ctr > 10) {
+		if (ctr > 100) {
 			DEBUG("unable to find random point on curve for group %d, something's fishy", grp_num);
 			goto fail;
 		}
```
