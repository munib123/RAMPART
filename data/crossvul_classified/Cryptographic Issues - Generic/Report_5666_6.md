# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5666_6
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5666_6`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 48-88 of the vulnerable file.

	kfree(buf);
	return err;
}

static int crypto_init_rng_ops(struct crypto_tfm *tfm, u32 type, u32 mask)
{
	struct rng_alg *alg = &tfm->__crt_alg->cra_rng;
	struct rng_tfm *ops = &tfm->crt_rng;

	ops->rng_gen_random = alg->rng_make_random;
	ops->rng_reset = rngapi_reset;

	return 0;
}

#ifdef CONFIG_NET
static int crypto_rng_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_rng rrng;

	snprintf(rrng.type, CRYPTO_MAX_ALG_NAME, "%s", "rng");

	rrng.seedsize = alg->cra_rng.seedsize;

	if (nla_put(skb, CRYPTOCFGA_REPORT_RNG,
		    sizeof(struct crypto_report_rng), &rrng))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
#else
static int crypto_rng_report(struct sk_buff *skb, struct crypto_alg *alg)
{
	return -ENOSYS;
}
#endif

static void crypto_rng_show(struct seq_file *m, struct crypto_alg *alg)
	__attribute__ ((unused));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,7 +65,7 @@
 {
 	struct crypto_report_rng rrng;
 
-	snprintf(rrng.type, CRYPTO_MAX_ALG_NAME, "%s", "rng");
+	strncpy(rrng.type, "rng", sizeof(rrng.type));
 
 	rrng.seedsize = alg->cra_rng.seedsize;
 
```
