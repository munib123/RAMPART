# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2839_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2839_1`)

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

#ifndef _CRYPTO_INTERNAL_RNG_H
#define _CRYPTO_INTERNAL_RNG_H

#include <crypto/algapi.h>
#include <crypto/rng.h>

extern const struct crypto_type crypto_rng_type;

int crypto_register_rng(struct rng_alg *alg);
void crypto_unregister_rng(struct rng_alg *alg);
int crypto_register_rngs(struct rng_alg *algs, int count);
void crypto_unregister_rngs(struct rng_alg *algs, int count);

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
@@ -15,8 +16,6 @@
 
 #include <crypto/algapi.h>
 #include <crypto/rng.h>
-
-extern const struct crypto_type crypto_rng_type;
 
 int crypto_register_rng(struct rng_alg *alg);
 void crypto_unregister_rng(struct rng_alg *alg);
```
