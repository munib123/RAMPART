# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 460_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `460_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 67-107 of the vulnerable file.


		if (!match)
			continue;

		if (unlikely(!crypto_mod_get(q)))
			continue;

		alg = q;
		break;
	}

	up_read(&crypto_alg_sem);

	return alg;
}

static int crypto_report_cipher(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_cipher rcipher;

	strlcpy(rcipher.type, "cipher", sizeof(rcipher.type));

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

	strlcpy(rcomp.type, "compression", sizeof(rcomp.type));
	if (nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,7 +84,7 @@
 {
 	struct crypto_report_cipher rcipher;
 
-	strlcpy(rcipher.type, "cipher", sizeof(rcipher.type));
+	strncpy(rcipher.type, "cipher", sizeof(rcipher.type));
 
 	rcipher.blocksize = alg->cra_blocksize;
 	rcipher.min_keysize = alg->cra_cipher.cia_min_keysize;
@@ -103,7 +103,7 @@
 {
 	struct crypto_report_comp rcomp;
 
-	strlcpy(rcomp.type, "compression", sizeof(rcomp.type));
+	strncpy(rcomp.type, "compression", sizeof(rcomp.type));
 	if (nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS,
 		    sizeof(struct crypto_report_comp), &rcomp))
 		goto nla_put_failure;
@@ -117,7 +117,7 @@
 {
 	struct crypto_report_acomp racomp;
 
-	strlcpy(racomp.type, "acomp", sizeof(racomp.type));
+	strncpy(racomp.type, "acomp", sizeof(racomp.type));
 
 	if (nla_put(skb, CRYPTOCFGA_REPORT_ACOMP,
 		    sizeof(struct crypto_report_acomp), &racomp))
@@ -132,7 +132,7 @@
 {
 	struct crypto_report_akcipher rakcipher;
 
-	strlcpy(rakcipher.type, "akcipher", sizeof(rakcipher.type));
+	strncpy(rakcipher.type, "akcipher", sizeof(rakcipher.type));
 
 	if (nla_put(skb, CRYPTOCFGA_REPORT_AKCIPHER,
 		    sizeof(struct crypto_report_akcipher), &rakcipher))
@@ -147,7 +147,7 @@
 {
 	struct crypto_report_kpp rkpp;
 
-	strlcpy(rkpp.type, "kpp", sizeof(rkpp.type));
+	strncpy(rkpp.type, "kpp", sizeof(rkpp.type));
 
 	if (nla_put(skb, CRYPTOCFGA_REPORT_KPP,
 		    sizeof(struct crypto_report_kpp), &rkpp))
@@ -161,10 +161,10 @@
 static int crypto_report_one(struct crypto_alg *alg,
 			     struct crypto_user_alg *ualg, struct sk_buff *skb)
 {
-	strlcpy(ualg->cru_name, alg->cra_name, sizeof(ualg->cru_name));
-	strlcpy(ualg->cru_driver_name, alg->cra_driver_name,
+	strncpy(ualg->cru_name, alg->cra_name, sizeof(ualg->cru_name));
+	strncpy(ualg->cru_driver_name, alg->cra_driver_name,
 		sizeof(ualg->cru_driver_name));
-	strlcpy(ualg->cru_module_name, module_name(alg->cra_module),
+	strncpy(ualg->cru_module_name, module_name(alg->cra_module),
 		sizeof(ualg->cru_module_name));
 
 	ualg->cru_type = 0;
@@ -177,7 +177,7 @@
 	if (alg->cra_flags & CRYPTO_ALG_LARVAL) {
 		struct crypto_report_larval rl;
 
-		strlcpy(rl.type, "larval", sizeof(rl.type));
+		strncpy(rl.type, "larval", sizeof(rl.type));
 		if (nla_put(skb, CRYPTOCFGA_REPORT_LARVAL,
 			    sizeof(struct crypto_report_larval), &rl))
 			goto nla_put_failure;
```
