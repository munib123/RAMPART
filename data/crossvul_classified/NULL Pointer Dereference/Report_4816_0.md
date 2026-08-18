# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4816_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4816_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 237-277 of the vulnerable file.

	err = -ENAMETOOLONG;
	if (snprintf(inst->alg.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		    "mcryptd(%s)", alg->cra_driver_name) >= CRYPTO_MAX_ALG_NAME)
		goto out_free_inst;

	memcpy(inst->alg.cra_name, alg->cra_name, CRYPTO_MAX_ALG_NAME);

	inst->alg.cra_priority = alg->cra_priority + 50;
	inst->alg.cra_blocksize = alg->cra_blocksize;
	inst->alg.cra_alignmask = alg->cra_alignmask;

out:
	return p;

out_free_inst:
	kfree(p);
	p = ERR_PTR(err);
	goto out;
}

static inline void mcryptd_check_internal(struct rtattr **tb, u32 *type,
					  u32 *mask)
{
	struct crypto_attr_type *algt;

	algt = crypto_get_attr_type(tb);
	if (IS_ERR(algt))
		return;
	if ((algt->type & CRYPTO_ALG_INTERNAL))
		*type |= CRYPTO_ALG_INTERNAL;
	if ((algt->mask & CRYPTO_ALG_INTERNAL))
		*mask |= CRYPTO_ALG_INTERNAL;
}

static int mcryptd_hash_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_instance *inst = crypto_tfm_alg_instance(tfm);
	struct hashd_instance_ctx *ictx = crypto_instance_ctx(inst);
	struct crypto_ahash_spawn *spawn = &ictx->spawn;
	struct mcryptd_hash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_ahash *hash;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,18 +254,22 @@
 	goto out;
 }
 
-static inline void mcryptd_check_internal(struct rtattr **tb, u32 *type,
+static inline bool mcryptd_check_internal(struct rtattr **tb, u32 *type,
 					  u32 *mask)
 {
 	struct crypto_attr_type *algt;
 
 	algt = crypto_get_attr_type(tb);
 	if (IS_ERR(algt))
-		return;
-	if ((algt->type & CRYPTO_ALG_INTERNAL))
-		*type |= CRYPTO_ALG_INTERNAL;
-	if ((algt->mask & CRYPTO_ALG_INTERNAL))
-		*mask |= CRYPTO_ALG_INTERNAL;
+		return false;
+
+	*type |= algt->type & CRYPTO_ALG_INTERNAL;
+	*mask |= algt->mask & CRYPTO_ALG_INTERNAL;
+
+	if (*type & *mask & CRYPTO_ALG_INTERNAL)
+		return true;
+	else
+		return false;
 }
 
 static int mcryptd_hash_init_tfm(struct crypto_tfm *tfm)
@@ -492,7 +496,8 @@
 	u32 mask = 0;
 	int err;
 
-	mcryptd_check_internal(tb, &type, &mask);
+	if (!mcryptd_check_internal(tb, &type, &mask))
+		return -EINVAL;
 
 	halg = ahash_attr_alg(tb[1], type, mask);
 	if (IS_ERR(halg))
```
