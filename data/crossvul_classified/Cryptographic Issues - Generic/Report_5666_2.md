# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5666_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5666_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 387-427 of the vulnerable file.

		hash->export = alg->export;
	if (alg->import)
		hash->import = alg->import;

	return 0;
}

static unsigned int crypto_ahash_extsize(struct crypto_alg *alg)
{
	if (alg->cra_type == &crypto_ahash_type)
		return alg->cra_ctxsize;

	return sizeof(struct crypto_shash *);
}

#ifdef CONFIG_NET
static int crypto_ahash_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_hash rhash;

	snprintf(rhash.type, CRYPTO_MAX_ALG_NAME, "%s", "ahash");

	rhash.blocksize = alg->cra_blocksize;
	rhash.digestsize = __crypto_hash_alg_common(alg)->digestsize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_HASH,
		    sizeof(struct crypto_report_hash), &rhash))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
#else
static int crypto_ahash_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif

static void crypto_ahash_show(struct seq_file *m, struct crypto_alg *alg)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -404,7 +404,7 @@
 {
 	struct crypto_report_hash rhash;
 
-	snprintf(rhash.type, CRYPTO_MAX_ALG_NAME, "%s", "ahash");
+	strncpy(rhash.type, "ahash", sizeof(rhash.type));
 
 	rhash.blocksize = alg->cra_blocksize;
 	rhash.digestsize = __crypto_hash_alg_common(alg)->digestsize;
```
