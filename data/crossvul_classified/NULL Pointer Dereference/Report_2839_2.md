# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2839_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2839_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-25 of the vulnerable file.

/*
 * RNG: Random Number Generator  algorithms under the crypto API
 *
 * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef _CRYPTO_RNG_H
#define _CRYPTO_RNG_H

#include <linux/crypto.h>

struct crypto_rng;

/**
 * struct rng_alg - random number generator definition
 *
 * @generate:	The function defined by this variable obtains a
 *		random number. The random number generator transform
 *		must generate the random number out of the context
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,6 +2,7 @@
  * RNG: Random Number Generator  algorithms under the crypto API
  *
  * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
+ * Copyright (c) 2015 Herbert Xu <herbert@gondor.apana.org.au>
  *
  * This program is free software; you can redistribute it and/or modify it
  * under the terms of the GNU General Public License as published by the Free
@@ -56,11 +57,6 @@
 };
 
 struct crypto_rng {
-	int (*generate)(struct crypto_rng *tfm,
-			const u8 *src, unsigned int slen,
-			u8 *dst, unsigned int dlen);
-	int (*seed)(struct crypto_rng *tfm, const u8 *seed, unsigned int slen);
-	unsigned int seedsize;
 	struct crypto_tfm base;
 };
 
@@ -144,7 +140,7 @@
 				      const u8 *src, unsigned int slen,
 				      u8 *dst, unsigned int dlen)
 {
-	return tfm->generate(tfm, src, slen, dst, dlen);
+	return crypto_rng_alg(tfm)->generate(tfm, src, slen, dst, dlen);
 }
 
 /**
@@ -198,7 +194,7 @@
  */
 static inline int crypto_rng_seedsize(struct crypto_rng *tfm)
 {
-	return tfm->seedsize;
+	return crypto_rng_alg(tfm)->seedsize;
 }
 
 #endif
```
