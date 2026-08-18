# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5666_4
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5666_4`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 58-98 of the vulnerable file.

			match = !strcmp(q->cra_driver_name,
					p->cru_driver_name);
		else if (!exact)
			match = !strcmp(q->cra_name, p->cru_name);

		if (match) {
			alg = q;
			break;
		}
	}

	up_read(&crypto_alg_sem);

	return alg;
}

static int crypto_report_cipher(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_cipher rcipher;

	snprintf(rcipher.type, CRYPTO_MAX_ALG_NAME, "%s", "cipher");

	rcipher.blocksize = alg->cra_blocksize;
	rcipher.min_keysize = alg->cra_cipher.cia_min_keysize;
	rcipher.max_keysize = alg->cra_cipher.cia_max_keysize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_CIPHER,
		    sizeof(struct crypto_report_cipher), &rcipher))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static int crypto_report_comp(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_comp rcomp;

	snprintf(rcomp.type, CRYPTO_MAX_ALG_NAME, "%s", "compression");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
 {
 	struct crypto_report_cipher rcipher;
 
-	snprintf(rcipher.type, CRYPTO_MAX_ALG_NAME, "%s", "cipher");
+	strncpy(rcipher.type, "cipher", sizeof(rcipher.type));
 
 	rcipher.blocksize = alg->cra_blocksize;
 	rcipher.min_keysize = alg->cra_cipher.cia_min_keysize;
@@ -94,8 +94,7 @@
 {
 	struct crypto_report_comp rcomp;
 
-	snprintf(rcomp.type, CRYPTO_MAX_ALG_NAME, "%s", "compression");
-
+	strncpy(rcomp.type, "compression", sizeof(rcomp.type));
 	if (nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS,
 		    sizeof(struct crypto_report_comp), &rcomp))
 		goto nla_put_failure;
@@ -108,12 +107,14 @@
 static int crypto_report_one(struct crypto_alg *alg,
 			     struct crypto_user_alg *ualg, struct sk_buff *skb)
 {
-	memcpy(&ualg->cru_name, &alg->cra_name, sizeof(ualg->cru_name));
-	memcpy(&ualg->cru_driver_name, &alg->cra_driver_name,
-	       sizeof(ualg->cru_driver_name));
-	memcpy(&ualg->cru_module_name, module_name(alg->cra_module),
-	       CRYPTO_MAX_ALG_NAME);
-
+	strncpy(ualg->cru_name, alg->cra_name, sizeof(ualg->cru_name));
+	strncpy(ualg->cru_driver_name, alg->cra_driver_name,
+		sizeof(ualg->cru_driver_name));
+	strncpy(ualg->cru_module_name, module_name(alg->cra_module),
+		sizeof(ualg->cru_module_name));
+
+	ualg->cru_type = 0;
+	ualg->cru_mask = 0;
 	ualg->cru_flags = alg->cra_flags;
 	ualg->cru_refcnt = atomic_read(&alg->cra_refcnt);
 
@@ -122,8 +123,7 @@
 	if (alg->cra_flags & CRYPTO_ALG_LARVAL) {
 		struct crypto_report_larval rl;
 
-		snprintf(rl.type, CRYPTO_MAX_ALG_NAME, "%s", "larval");
-
+		strncpy(rl.type, "larval", sizeof(rl.type));
 		if (nla_put(skb, CRYPTOCFGA_REPORT_LARVAL,
 			    sizeof(struct crypto_report_larval), &rl))
 			goto nla_put_failure;
```
