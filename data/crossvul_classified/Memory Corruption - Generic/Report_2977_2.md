# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 2977_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2977_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 64-104 of the vulnerable file.

	return crypto_hash_walk_done(walk, err);
}

static inline int crypto_hash_walk_last(struct crypto_hash_walk *walk)
{
	return !(walk->entrylen | walk->total);
}

static inline int crypto_ahash_walk_last(struct crypto_hash_walk *walk)
{
	return crypto_hash_walk_last(walk);
}

int crypto_register_ahash(struct ahash_alg *alg);
int crypto_unregister_ahash(struct ahash_alg *alg);
int crypto_register_ahashes(struct ahash_alg *algs, int count);
void crypto_unregister_ahashes(struct ahash_alg *algs, int count);
int ahash_register_instance(struct crypto_template *tmpl,
			    struct ahash_instance *inst);
void ahash_free_instance(struct crypto_instance *inst);

int crypto_init_ahash_spawn(struct crypto_ahash_spawn *spawn,
			    struct hash_alg_common *alg,
			    struct crypto_instance *inst);

static inline void crypto_drop_ahash(struct crypto_ahash_spawn *spawn)
{
	crypto_drop_spawn(&spawn->base);
}

struct hash_alg_common *ahash_attr_alg(struct rtattr *rta, u32 type, u32 mask);

int crypto_register_shash(struct shash_alg *alg);
int crypto_unregister_shash(struct shash_alg *alg);
int crypto_register_shashes(struct shash_alg *algs, int count);
int crypto_unregister_shashes(struct shash_alg *algs, int count);
int shash_register_instance(struct crypto_template *tmpl,
			    struct shash_instance *inst);
void shash_free_instance(struct crypto_instance *inst);

int crypto_init_shash_spawn(struct crypto_shash_spawn *spawn,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,6 +82,14 @@
 			    struct ahash_instance *inst);
 void ahash_free_instance(struct crypto_instance *inst);
 
+int shash_no_setkey(struct crypto_shash *tfm, const u8 *key,
+		    unsigned int keylen);
+
+static inline bool crypto_shash_alg_has_setkey(struct shash_alg *alg)
+{
+	return alg->setkey != shash_no_setkey;
+}
+
 int crypto_init_ahash_spawn(struct crypto_ahash_spawn *spawn,
 			    struct hash_alg_common *alg,
 			    struct crypto_instance *inst);
```
