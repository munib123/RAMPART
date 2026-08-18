# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5666_7
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5666_7`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 513-553 of the vulnerable file.


static int crypto_shash_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_shash *hash = __crypto_shash_cast(tfm);

	hash->descsize = crypto_shash_alg(hash)->descsize;
	return 0;
}

static unsigned int crypto_shash_extsize(struct crypto_alg *alg)
{
	return alg->cra_ctxsize;
}

#ifdef CONFIG_NET
static int crypto_shash_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_hash rhash;
	struct shash_alg *salg = __crypto_shash_alg(alg);

	snprintf(rhash.type, CRYPTO_MAX_ALG_NAME, "%s", "shash");
	rhash.blocksize = alg->cra_blocksize;
	rhash.digestsize = salg->digestsize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_HASH,
		    sizeof(struct crypto_report_hash), &rhash))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
#else
static int crypto_shash_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif

static void crypto_shash_show(struct seq_file *m, struct crypto_alg *alg)
	__attribute__ ((unused));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -530,7 +530,8 @@
 	struct crypto_report_hash rhash;
 	struct shash_alg *salg = __crypto_shash_alg(alg);
 
-	snprintf(rhash.type, CRYPTO_MAX_ALG_NAME, "%s", "shash");
+	strncpy(rhash.type, "shash", sizeof(rhash.type));
+
 	rhash.blocksize = alg->cra_blocksize;
 	rhash.digestsize = salg->digestsize;
 
```
