# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5666_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5666_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 371-413 of the vulnerable file.

		return -EINVAL;

	crt->setkey = setkey;
	crt->encrypt = alg->encrypt;
	crt->decrypt = alg->decrypt;
	if (!alg->ivsize) {
		crt->givencrypt = skcipher_null_givencrypt;
		crt->givdecrypt = skcipher_null_givdecrypt;
	}
	crt->base = __crypto_ablkcipher_cast(tfm);
	crt->ivsize = alg->ivsize;

	return 0;
}

#ifdef CONFIG_NET
static int crypto_ablkcipher_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_blkcipher rblkcipher;

	snprintf(rblkcipher.type, CRYPTO_MAX_ALG_NAME, "%s", "ablkcipher");
	snprintf(rblkcipher.geniv, CRYPTO_MAX_ALG_NAME, "%s",
		 alg->cra_ablkcipher.geniv ?: "<default>");

	rblkcipher.blocksize = alg->cra_blocksize;
	rblkcipher.min_keysize = alg->cra_ablkcipher.min_keysize;
	rblkcipher.max_keysize = alg->cra_ablkcipher.max_keysize;
	rblkcipher.ivsize = alg->cra_ablkcipher.ivsize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_BLKCIPHER,
		    sizeof(struct crypto_report_blkcipher), &rblkcipher))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
#else
static int crypto_ablkcipher_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -388,9 +388,9 @@
 {
 	struct crypto_report_blkcipher rblkcipher;
 
-	snprintf(rblkcipher.type, CRYPTO_MAX_ALG_NAME, "%s", "ablkcipher");
-	snprintf(rblkcipher.geniv, CRYPTO_MAX_ALG_NAME, "%s",
-		 alg->cra_ablkcipher.geniv ?: "<default>");
+	strncpy(rblkcipher.type, "ablkcipher", sizeof(rblkcipher.type));
+	strncpy(rblkcipher.geniv, alg->cra_ablkcipher.geniv ?: "<default>",
+		sizeof(rblkcipher.geniv));
 
 	rblkcipher.blocksize = alg->cra_blocksize;
 	rblkcipher.min_keysize = alg->cra_ablkcipher.min_keysize;
@@ -469,9 +469,9 @@
 {
 	struct crypto_report_blkcipher rblkcipher;
 
-	snprintf(rblkcipher.type, CRYPTO_MAX_ALG_NAME, "%s", "givcipher");
-	snprintf(rblkcipher.geniv, CRYPTO_MAX_ALG_NAME, "%s",
-		 alg->cra_ablkcipher.geniv ?: "<built-in>");
+	strncpy(rblkcipher.type, "givcipher", sizeof(rblkcipher.type));
+	strncpy(rblkcipher.geniv, alg->cra_ablkcipher.geniv ?: "<built-in>",
+		sizeof(rblkcipher.geniv));
 
 	rblkcipher.blocksize = alg->cra_blocksize;
 	rblkcipher.min_keysize = alg->cra_ablkcipher.min_keysize;
```
