# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2977_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2977_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 178-218 of the vulnerable file.

	struct hmac_ctx *ctx = hmac_ctx(__crypto_shash_cast(tfm));
	crypto_free_shash(ctx->hash);
}

static int hmac_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	struct shash_instance *inst;
	struct crypto_alg *alg;
	struct shash_alg *salg;
	int err;
	int ds;
	int ss;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_SHASH);
	if (err)
		return err;

	salg = shash_attr_alg(tb[1], 0, 0);
	if (IS_ERR(salg))
		return PTR_ERR(salg);

	err = -EINVAL;
	ds = salg->digestsize;
	ss = salg->statesize;
	alg = &salg->base;
	if (ds > alg->cra_blocksize ||
	    ss < alg->cra_blocksize)
		goto out_put_alg;

	inst = shash_alloc_instance("hmac", alg);
	err = PTR_ERR(inst);
	if (IS_ERR(inst))
		goto out_put_alg;

	err = crypto_init_shash_spawn(shash_instance_ctx(inst), salg,
				      shash_crypto_instance(inst));
	if (err)
		goto out_free_inst;

	inst->alg.base.cra_priority = alg->cra_priority;
	inst->alg.base.cra_blocksize = alg->cra_blocksize;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -195,11 +195,15 @@
 	salg = shash_attr_alg(tb[1], 0, 0);
 	if (IS_ERR(salg))
 		return PTR_ERR(salg);
-
+	alg = &salg->base;
+
+	/* The underlying hash algorithm must be unkeyed */
 	err = -EINVAL;
+	if (crypto_shash_alg_has_setkey(salg))
+		goto out_put_alg;
+
 	ds = salg->digestsize;
 	ss = salg->statesize;
-	alg = &salg->base;
 	if (ds > alg->cra_blocksize ||
 	    ss < alg->cra_blocksize)
 		goto out_put_alg;
```
