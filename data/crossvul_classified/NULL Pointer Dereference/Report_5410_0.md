# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5410_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5410_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1-32 of the vulnerable file.

/* Large capacity key type
 *
 * Copyright (C) 2013 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/shmem_fs.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <keys/user-type.h>
#include <keys/big_key-type.h>
#include <crypto/rng.h>
#include <crypto/skcipher.h>

/*
 * Layout of key payload words.
 */
enum {
	big_key_data,
	big_key_path,
	big_key_path_2nd_part,
	big_key_len,
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,6 +9,7 @@
  * 2 of the Licence, or (at your option) any later version.
  */
 
+#define pr_fmt(fmt) "big_key: "fmt
 #include <linux/init.h>
 #include <linux/seq_file.h>
 #include <linux/file.h>
@@ -341,44 +342,48 @@
  */
 static int __init big_key_init(void)
 {
-	return register_key_type(&key_type_big_key);
-}
-
-/*
- * Initialize big_key crypto and RNG algorithms
- */
-static int __init big_key_crypto_init(void)
-{
-	int ret = -EINVAL;
-
-	/* init RNG */
-	big_key_rng = crypto_alloc_rng(big_key_rng_name, 0, 0);
-	if (IS_ERR(big_key_rng)) {
-		big_key_rng = NULL;
-		return -EFAULT;
-	}
+	struct crypto_skcipher *cipher;
+	struct crypto_rng *rng;
+	int ret;
+
+	rng = crypto_alloc_rng(big_key_rng_name, 0, 0);
+	if (IS_ERR(rng)) {
+		pr_err("Can't alloc rng: %ld\n", PTR_ERR(rng));
+		return PTR_ERR(rng);
+	}
+
+	big_key_rng = rng;
 
 	/* seed RNG */
-	ret = crypto_rng_reset(big_key_rng, NULL, crypto_rng_seedsize(big_key_rng));
-	if (ret)
-		goto error;
+	ret = crypto_rng_reset(rng, NULL, crypto_rng_seedsize(rng));
+	if (ret) {
+		pr_err("Can't reset rng: %d\n", ret);
+		goto error_rng;
+	}
 
 	/* init block cipher */
-	big_key_skcipher = crypto_alloc_skcipher(big_key_alg_name,
-						 0, CRYPTO_ALG_ASYNC);
-	if (IS_ERR(big_key_skcipher)) {
-		big_key_skcipher = NULL;
-		ret = -EFAULT;
-		goto error;
+	cipher = crypto_alloc_skcipher(big_key_alg_name, 0, CRYPTO_ALG_ASYNC);
+	if (IS_ERR(cipher)) {
+		ret = PTR_ERR(cipher);
+		pr_err("Can't alloc crypto: %d\n", ret);
+		goto error_rng;
+	}
+
+	big_key_skcipher = cipher;
+
+	ret = register_key_type(&key_type_big_key);
+	if (ret < 0) {
+		pr_err("Can't register type: %d\n", ret);
+		goto error_cipher;
 	}
 
 	return 0;
 
-error:
+error_cipher:
+	crypto_free_skcipher(big_key_skcipher);
+error_rng:
 	crypto_free_rng(big_key_rng);
-	big_key_rng = NULL;
 	return ret;
 }
 
-device_initcall(big_key_init);
-late_initcall(big_key_crypto_init);
+late_initcall(big_key_init);
```
