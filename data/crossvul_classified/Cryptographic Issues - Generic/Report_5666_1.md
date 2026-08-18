# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5666_1
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5666_1`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 100-142 of the vulnerable file.


	crt->setkey = tfm->__crt_alg->cra_flags & CRYPTO_ALG_GENIV ?
		      alg->setkey : setkey;
	crt->encrypt = alg->encrypt;
	crt->decrypt = alg->decrypt;
	crt->givencrypt = alg->givencrypt ?: no_givcrypt;
	crt->givdecrypt = alg->givdecrypt ?: no_givcrypt;
	crt->base = __crypto_aead_cast(tfm);
	crt->ivsize = alg->ivsize;
	crt->authsize = alg->maxauthsize;

	return 0;
}

#ifdef CONFIG_NET
static int crypto_aead_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_aead raead;
	struct aead_alg *aead = &alg->cra_aead;

	snprintf(raead.type, CRYPTO_MAX_ALG_NAME, "%s", "aead");
	snprintf(raead.geniv, CRYPTO_MAX_ALG_NAME, "%s",
		 aead->geniv ?: "<built-in>");

	raead.blocksize = alg->cra_blocksize;
	raead.maxauthsize = aead->maxauthsize;
	raead.ivsize = aead->ivsize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_AEAD,
		    sizeof(struct crypto_report_aead), &raead))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
#else
static int crypto_aead_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,9 +117,8 @@
 	struct crypto_report_aead raead;
 	struct aead_alg *aead = &alg->cra_aead;
 
-	snprintf(raead.type, CRYPTO_MAX_ALG_NAME, "%s", "aead");
-	snprintf(raead.geniv, CRYPTO_MAX_ALG_NAME, "%s",
-		 aead->geniv ?: "<built-in>");
+	strncpy(raead.type, "aead", sizeof(raead.type));
+	strncpy(raead.geniv, aead->geniv ?: "<built-in>", sizeof(raead.geniv));
 
 	raead.blocksize = alg->cra_blocksize;
 	raead.maxauthsize = aead->maxauthsize;
@@ -203,8 +202,8 @@
 	struct crypto_report_aead raead;
 	struct aead_alg *aead = &alg->cra_aead;
 
-	snprintf(raead.type, CRYPTO_MAX_ALG_NAME, "%s", "nivaead");
-	snprintf(raead.geniv, CRYPTO_MAX_ALG_NAME, "%s", aead->geniv);
+	strncpy(raead.type, "nivaead", sizeof(raead.type));
+	strncpy(raead.geniv, aead->geniv, sizeof(raead.geniv));
 
 	raead.blocksize = alg->cra_blocksize;
 	raead.maxauthsize = aead->maxauthsize;
```
