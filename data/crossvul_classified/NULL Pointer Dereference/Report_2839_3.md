# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2839_3
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2839_3`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 121-161 of the vulnerable file.

#define CRYPTO_MAX_ALG_NAME		64

/*
 * The macro CRYPTO_MINALIGN_ATTR (along with the void * type in the actual
 * declaration) is used to ensure that the crypto_tfm context structure is
 * aligned correctly for the given architecture so that there are no alignment
 * faults for C data types.  In particular, this is required on platforms such
 * as arm where pointers are 32-bit aligned but there are data types such as
 * u64 which require 64-bit alignment.
 */
#define CRYPTO_MINALIGN ARCH_KMALLOC_MINALIGN

#define CRYPTO_MINALIGN_ATTR __attribute__ ((__aligned__(CRYPTO_MINALIGN)))

struct scatterlist;
struct crypto_ablkcipher;
struct crypto_async_request;
struct crypto_aead;
struct crypto_blkcipher;
struct crypto_hash;
struct crypto_rng;
struct crypto_tfm;
struct crypto_type;
struct aead_givcrypt_request;
struct skcipher_givcrypt_request;

typedef void (*crypto_completion_t)(struct crypto_async_request *req, int err);

/**
 * DOC: Block Cipher Context Data Structures
 *
 * These data structures define the operating context for each block cipher
 * type.
 */

struct crypto_async_request {
	struct list_head list;
	crypto_completion_t complete;
	void *data;
	struct crypto_tfm *tfm;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -138,7 +138,6 @@
 struct crypto_aead;
 struct crypto_blkcipher;
 struct crypto_hash;
-struct crypto_rng;
 struct crypto_tfm;
 struct crypto_type;
 struct aead_givcrypt_request;
@@ -426,40 +425,12 @@
 			      unsigned int slen, u8 *dst, unsigned int *dlen);
 };
 
-/**
- * struct old_rng_alg - random number generator definition
- * @rng_make_random: The function defined by this variable obtains a random
- *		     number. The random number generator transform must generate
- *		     the random number out of the context provided with this
- *		     call.
- * @rng_reset: Reset of the random number generator by clearing the entire state.
- *	       With the invocation of this function call, the random number
- *             generator shall completely reinitialize its state. If the random
- *	       number generator requires a seed for setting up a new state,
- *	       the seed must be provided by the consumer while invoking this
- *	       function. The required size of the seed is defined with
- *	       @seedsize .
- * @seedsize: The seed size required for a random number generator
- *	      initialization defined with this variable. Some random number
- *	      generators like the SP800-90A DRBG does not require a seed as the
- *	      seeding is implemented internally without the need of support by
- *	      the consumer. In this case, the seed size is set to zero.
- */
-struct old_rng_alg {
-	int (*rng_make_random)(struct crypto_rng *tfm, u8 *rdata,
-			       unsigned int dlen);
-	int (*rng_reset)(struct crypto_rng *tfm, u8 *seed, unsigned int slen);
-
-	unsigned int seedsize;
-};
-
 
 #define cra_ablkcipher	cra_u.ablkcipher
 #define cra_aead	cra_u.aead
 #define cra_blkcipher	cra_u.blkcipher
 #define cra_cipher	cra_u.cipher
 #define cra_compress	cra_u.compress
-#define cra_rng		cra_u.rng
 
 /**
  * struct crypto_alg - definition of a cryptograpic cipher algorithm
@@ -559,7 +530,6 @@
 		struct blkcipher_alg blkcipher;
 		struct cipher_alg cipher;
 		struct compress_alg compress;
-		struct old_rng_alg rng;
 	} cra_u;
 
 	int (*cra_init)(struct crypto_tfm *tfm);
```
