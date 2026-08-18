# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2976_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2976_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 42-88 of the vulnerable file.

{
	struct salsa20_ctx *ctx = crypto_tfm_ctx(tfm);
	salsa20_keysetup(ctx, key, keysize*8, SALSA20_IV_SIZE*8);
	return 0;
}

static int encrypt(struct blkcipher_desc *desc,
		   struct scatterlist *dst, struct scatterlist *src,
		   unsigned int nbytes)
{
	struct blkcipher_walk walk;
	struct crypto_blkcipher *tfm = desc->tfm;
	struct salsa20_ctx *ctx = crypto_blkcipher_ctx(tfm);
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt_block(desc, &walk, 64);

	salsa20_ivsetup(ctx, walk.iv);

	if (likely(walk.nbytes == nbytes))
	{
		salsa20_encrypt_bytes(ctx, walk.src.virt.addr,
				      walk.dst.virt.addr, nbytes);
		return blkcipher_walk_done(desc, &walk, 0);
	}

	while (walk.nbytes >= 64) {
		salsa20_encrypt_bytes(ctx, walk.src.virt.addr,
				      walk.dst.virt.addr,
				      walk.nbytes - (walk.nbytes % 64));
		err = blkcipher_walk_done(desc, &walk, walk.nbytes % 64);
	}

	if (walk.nbytes) {
		salsa20_encrypt_bytes(ctx, walk.src.virt.addr,
				      walk.dst.virt.addr, walk.nbytes);
		err = blkcipher_walk_done(desc, &walk, 0);
	}

	return err;
}

static struct crypto_alg alg = {
	.cra_name           =   "salsa20",
	.cra_driver_name    =   "salsa20-asm",
	.cra_priority       =   200,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,13 +59,6 @@
 
 	salsa20_ivsetup(ctx, walk.iv);
 
-	if (likely(walk.nbytes == nbytes))
-	{
-		salsa20_encrypt_bytes(ctx, walk.src.virt.addr,
-				      walk.dst.virt.addr, nbytes);
-		return blkcipher_walk_done(desc, &walk, 0);
-	}
-
 	while (walk.nbytes >= 64) {
 		salsa20_encrypt_bytes(ctx, walk.src.virt.addr,
 				      walk.dst.virt.addr,
```
