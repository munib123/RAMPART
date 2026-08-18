# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3370_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3370_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 747-787 of the vulnerable file.

		crypto_mod_put(calg);
		return PTR_ERR(abtfm);
	}

	ablkcipher = __crypto_ablkcipher_cast(abtfm);
	*ctx = ablkcipher;
	tfm->exit = crypto_exit_skcipher_ops_ablkcipher;

	skcipher->setkey = skcipher_setkey_ablkcipher;
	skcipher->encrypt = skcipher_encrypt_ablkcipher;
	skcipher->decrypt = skcipher_decrypt_ablkcipher;

	skcipher->ivsize = crypto_ablkcipher_ivsize(ablkcipher);
	skcipher->reqsize = crypto_ablkcipher_reqsize(ablkcipher) +
			    sizeof(struct ablkcipher_request);
	skcipher->keysize = calg->cra_ablkcipher.max_keysize;

	return 0;
}

static void crypto_skcipher_exit_tfm(struct crypto_tfm *tfm)
{
	struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);
	struct skcipher_alg *alg = crypto_skcipher_alg(skcipher);

	alg->exit(skcipher);
}

static int crypto_skcipher_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);
	struct skcipher_alg *alg = crypto_skcipher_alg(skcipher);

	if (tfm->__crt_alg->cra_type == &crypto_blkcipher_type)
		return crypto_init_skcipher_ops_blkcipher(tfm);

	if (tfm->__crt_alg->cra_type == &crypto_ablkcipher_type ||
	    tfm->__crt_alg->cra_type == &crypto_givcipher_type)
		return crypto_init_skcipher_ops_ablkcipher(tfm);

	skcipher->setkey = alg->setkey;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -764,6 +764,44 @@
 	return 0;
 }
 
+static int skcipher_setkey_unaligned(struct crypto_skcipher *tfm,
+				     const u8 *key, unsigned int keylen)
+{
+	unsigned long alignmask = crypto_skcipher_alignmask(tfm);
+	struct skcipher_alg *cipher = crypto_skcipher_alg(tfm);
+	u8 *buffer, *alignbuffer;
+	unsigned long absize;
+	int ret;
+
+	absize = keylen + alignmask;
+	buffer = kmalloc(absize, GFP_ATOMIC);
+	if (!buffer)
+		return -ENOMEM;
+
+	alignbuffer = (u8 *)ALIGN((unsigned long)buffer, alignmask + 1);
+	memcpy(alignbuffer, key, keylen);
+	ret = cipher->setkey(tfm, alignbuffer, keylen);
+	kzfree(buffer);
+	return ret;
+}
+
+static int skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
+			   unsigned int keylen)
+{
+	struct skcipher_alg *cipher = crypto_skcipher_alg(tfm);
+	unsigned long alignmask = crypto_skcipher_alignmask(tfm);
+
+	if (keylen < cipher->min_keysize || keylen > cipher->max_keysize) {
+		crypto_skcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
+		return -EINVAL;
+	}
+
+	if ((unsigned long)key & alignmask)
+		return skcipher_setkey_unaligned(tfm, key, keylen);
+
+	return cipher->setkey(tfm, key, keylen);
+}
+
 static void crypto_skcipher_exit_tfm(struct crypto_tfm *tfm)
 {
 	struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);
@@ -784,7 +822,7 @@
 	    tfm->__crt_alg->cra_type == &crypto_givcipher_type)
 		return crypto_init_skcipher_ops_ablkcipher(tfm);
 
-	skcipher->setkey = alg->setkey;
+	skcipher->setkey = skcipher_setkey;
 	skcipher->encrypt = alg->encrypt;
 	skcipher->decrypt = alg->decrypt;
 	skcipher->ivsize = alg->ivsize;
```
