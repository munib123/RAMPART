# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2977_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2977_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 8-49 of the vulnerable file.

 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/scatterwalk.h>
#include <crypto/internal/hash.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/cryptouser.h>
#include <net/netlink.h>
#include <linux/compiler.h>

#include "internal.h"

static const struct crypto_type crypto_shash_type;

static int shash_no_setkey(struct crypto_shash *tfm, const u8 *key,
			   unsigned int keylen)
{
	return -ENOSYS;
}

static int shash_setkey_unaligned(struct crypto_shash *tfm, const u8 *key,
				  unsigned int keylen)
{
	struct shash_alg *shash = crypto_shash_alg(tfm);
	unsigned long alignmask = crypto_shash_alignmask(tfm);
	unsigned long absize;
	u8 *buffer, *alignbuffer;
	int err;

	absize = keylen + (alignmask & ~(crypto_tfm_ctx_alignment() - 1));
	buffer = kmalloc(absize, GFP_ATOMIC);
	if (!buffer)
		return -ENOMEM;

	alignbuffer = (u8 *)ALIGN((unsigned long)buffer, alignmask + 1);
	memcpy(alignbuffer, key, keylen);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,11 +25,12 @@
 
 static const struct crypto_type crypto_shash_type;
 
-static int shash_no_setkey(struct crypto_shash *tfm, const u8 *key,
-			   unsigned int keylen)
+int shash_no_setkey(struct crypto_shash *tfm, const u8 *key,
+		    unsigned int keylen)
 {
 	return -ENOSYS;
 }
+EXPORT_SYMBOL_GPL(shash_no_setkey);
 
 static int shash_setkey_unaligned(struct crypto_shash *tfm, const u8 *key,
 				  unsigned int keylen)
```
