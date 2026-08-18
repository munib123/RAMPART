# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2839_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2839_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-27 of the vulnerable file.

/*
 * Cryptographic API.
 *
 * RNG operations.
 *
 * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <linux/atomic.h>
#include <crypto/internal/rng.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/cryptouser.h>
#include <net/netlink.h>

#include "internal.h"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,6 +4,7 @@
  * RNG operations.
  *
  * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
+ * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
  *
  * This program is free software; you can redistribute it and/or modify it
  * under the terms of the GNU General Public License as published by the Free
@@ -36,39 +37,6 @@
 	return container_of(tfm, struct crypto_rng, base);
 }
 
-static inline struct old_rng_alg *crypto_old_rng_alg(struct crypto_rng *tfm)
-{
-	return &crypto_rng_tfm(tfm)->__crt_alg->cra_rng;
-}
-
-static int generate(struct crypto_rng *tfm, const u8 *src, unsigned int slen,
-		    u8 *dst, unsigned int dlen)
-{
-	return crypto_old_rng_alg(tfm)->rng_make_random(tfm, dst, dlen);
-}
-
-static int rngapi_reset(struct crypto_rng *tfm, const u8 *seed,
-			unsigned int slen)
-{
-	u8 *buf = NULL;
-	u8 *src = (u8 *)seed;
-	int err;
-
-	if (slen) {
-		buf = kmalloc(slen, GFP_KERNEL);
-		if (!buf)
-			return -ENOMEM;
-
-		memcpy(buf, seed, slen);
-		src = buf;
-	}
-
-	err = crypto_old_rng_alg(tfm)->rng_reset(tfm, src, slen);
-
-	kzfree(buf);
-	return err;
-}
-
 int crypto_rng_reset(struct crypto_rng *tfm, const u8 *seed, unsigned int slen)
 {
 	u8 *buf = NULL;
@@ -83,7 +51,7 @@
 		seed = buf;
 	}
 
-	err = tfm->seed(tfm, seed, slen);
+	err = crypto_rng_alg(tfm)->seed(tfm, seed, slen);
 
 	kfree(buf);
 	return err;
@@ -92,21 +60,6 @@
 
 static int crypto_rng_init_tfm(struct crypto_tfm *tfm)
 {
-	struct crypto_rng *rng = __crypto_rng_cast(tfm);
-	struct rng_alg *alg = crypto_rng_alg(rng);
-	struct old_rng_alg *oalg = crypto_old_rng_alg(rng);
-
-	if (oalg->rng_make_random) {
-		rng->generate = generate;
-		rng->seed = rngapi_reset;
-		rng->seedsize = oalg->seedsize;
-		return 0;
-	}
-
-	rng->generate = alg->generate;
-	rng->seed = alg->seed;
-	rng->seedsize = alg->seedsize;
-
 	return 0;
 }
 
@@ -114,8 +67,7 @@
 {
 	struct rng_alg *ralg = container_of(alg, struct rng_alg, base);
 
-	return alg->cra_rng.rng_make_random ?
-	       alg->cra_rng.seedsize : ralg->seedsize;
+	return ralg->seedsize;
 }
 
 #ifdef CONFIG_NET
@@ -150,7 +102,7 @@
 	seq_printf(m, "seedsize     : %u\n", seedsize(alg));
 }
 
-const struct crypto_type crypto_rng_type = {
+static const struct crypto_type crypto_rng_type = {
 	.extsize = crypto_alg_extsize,
 	.init_tfm = crypto_rng_init_tfm,
 #ifdef CONFIG_PROC_FS
@@ -162,7 +114,6 @@
 	.type = CRYPTO_ALG_TYPE_RNG,
 	.tfmsize = offsetof(struct crypto_rng, base),
 };
-EXPORT_SYMBOL_GPL(crypto_rng_type);
 
 struct crypto_rng *crypto_alloc_rng(const char *alg_name, u32 type, u32 mask)
 {
```
