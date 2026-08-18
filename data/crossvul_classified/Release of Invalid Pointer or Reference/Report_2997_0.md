# CrossVul Fix Pair: Release of Invalid Pointer or Reference in c
**Pair ID:** 2997_0
**Vulnerability Class:** Release of Invalid Pointer or Reference
**CWE:** CWE-763
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2997_0`)

## Vulnerability Information & PoC

## Description
Release of Invalid Pointer or Reference - This weakness can take several forms, such as: The memory was allocated, explicitly or implicitly, via one memory management method and deallocated using a different, non-compatible function (CWE-7...

## Vulnerable Code
```c
Lines 237-277 of the vulnerable file.

	cipher = crypto_spawn_aead(&ictx->spawn);

	if (IS_ERR(cipher))
		return PTR_ERR(cipher);

	ctx->child = cipher;
	crypto_aead_set_reqsize(tfm, sizeof(struct pcrypt_request) +
				     sizeof(struct aead_request) +
				     crypto_aead_reqsize(cipher));

	return 0;
}

static void pcrypt_aead_exit_tfm(struct crypto_aead *tfm)
{
	struct pcrypt_aead_ctx *ctx = crypto_aead_ctx(tfm);

	crypto_free_aead(ctx->child);
}

static int pcrypt_init_instance(struct crypto_instance *inst,
				struct crypto_alg *alg)
{
	if (snprintf(inst->alg.cra_driver_name, CRYPTO_MAX_ALG_NAME,
		     "pcrypt(%s)", alg->cra_driver_name) >= CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	memcpy(inst->alg.cra_name, alg->cra_name, CRYPTO_MAX_ALG_NAME);

	inst->alg.cra_priority = alg->cra_priority + 100;
	inst->alg.cra_blocksize = alg->cra_blocksize;
	inst->alg.cra_alignmask = alg->cra_alignmask;

	return 0;
}

static int pcrypt_create_aead(struct crypto_template *tmpl, struct rtattr **tb,
			      u32 type, u32 mask)
{
	struct pcrypt_instance_ctx *ctx;
	struct crypto_attr_type *algt;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,6 +254,14 @@
 	crypto_free_aead(ctx->child);
 }
 
+static void pcrypt_free(struct aead_instance *inst)
+{
+	struct pcrypt_instance_ctx *ctx = aead_instance_ctx(inst);
+
+	crypto_drop_aead(&ctx->spawn);
+	kfree(inst);
+}
+
 static int pcrypt_init_instance(struct crypto_instance *inst,
 				struct crypto_alg *alg)
 {
@@ -319,6 +327,8 @@
 	inst->alg.encrypt = pcrypt_aead_encrypt;
 	inst->alg.decrypt = pcrypt_aead_decrypt;
 
+	inst->free = pcrypt_free;
+
 	err = aead_register_instance(tmpl, inst);
 	if (err)
 		goto out_drop_aead;
@@ -347,14 +357,6 @@
 	}
 
 	return -EINVAL;
-}
-
-static void pcrypt_free(struct crypto_instance *inst)
-{
-	struct pcrypt_instance_ctx *ctx = crypto_instance_ctx(inst);
-
-	crypto_drop_aead(&ctx->spawn);
-	kfree(inst);
 }
 
 static int pcrypt_cpumask_change_notify(struct notifier_block *self,
@@ -469,7 +471,6 @@
 static struct crypto_template pcrypt_tmpl = {
 	.name = "pcrypt",
 	.create = pcrypt_create,
-	.free = pcrypt_free,
 	.module = THIS_MODULE,
 };
 
```
