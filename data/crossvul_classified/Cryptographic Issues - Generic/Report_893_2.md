# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 893_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `893_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 204-244 of the vulnerable file.

static unsigned int do_decrypt (const RIJNDAEL_context *ctx, unsigned char *bx,
                                const unsigned char *ax);




/* All the numbers.  */
#include "rijndael-tables.h"





/* Function prototypes.  */
static const char *selftest(void);




/* Prefetching for encryption/decryption tables. */
static void prefetch_table(const volatile byte *tab, size_t len)
{
  size_t i;

  for (i = 0; i < len; i += 8 * 32)
    {
      (void)tab[i + 0 * 32];
      (void)tab[i + 1 * 32];
      (void)tab[i + 2 * 32];
      (void)tab[i + 3 * 32];
      (void)tab[i + 4 * 32];
      (void)tab[i + 5 * 32];
      (void)tab[i + 6 * 32];
      (void)tab[i + 7 * 32];
    }

  (void)tab[len - 1];
}

static void prefetch_enc(void)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -221,11 +221,11 @@
 
 
 /* Prefetching for encryption/decryption tables. */
-static void prefetch_table(const volatile byte *tab, size_t len)
+static inline void prefetch_table(const volatile byte *tab, size_t len)
 {
   size_t i;
 
-  for (i = 0; i < len; i += 8 * 32)
+  for (i = 0; len - i >= 8 * 32; i += 8 * 32)
     {
       (void)tab[i + 0 * 32];
       (void)tab[i + 1 * 32];
@@ -236,17 +236,37 @@
       (void)tab[i + 6 * 32];
       (void)tab[i + 7 * 32];
     }
+  for (; i < len; i += 32)
+    {
+      (void)tab[i];
+    }
 
   (void)tab[len - 1];
 }
 
 static void prefetch_enc(void)
 {
-  prefetch_table((const void *)encT, sizeof(encT));
+  /* Modify counters to trigger copy-on-write and unsharing if physical pages
+   * of look-up table are shared between processes.  Modifying counters also
+   * causes checksums for pages to change and hint same-page merging algorithm
+   * that these pages are frequently changing.  */
+  enc_tables.counter_head++;
+  enc_tables.counter_tail++;
+
+  /* Prefetch look-up tables to cache.  */
+  prefetch_table((const void *)&enc_tables, sizeof(enc_tables));
 }
 
 static void prefetch_dec(void)
 {
+  /* Modify counters to trigger copy-on-write and unsharing if physical pages
+   * of look-up table are shared between processes.  Modifying counters also
+   * causes checksums for pages to change and hint same-page merging algorithm
+   * that these pages are frequently changing.  */
+  dec_tables.counter_head++;
+  dec_tables.counter_tail++;
+
+  /* Prefetch look-up tables to cache.  */
   prefetch_table((const void *)&dec_tables, sizeof(dec_tables));
 }
 
@@ -770,9 +790,10 @@
 {
 #ifdef USE_AMD64_ASM
   return _gcry_aes_amd64_encrypt_block(ctx->keyschenc, bx, ax, ctx->rounds,
-				       encT);
+				       enc_tables.T);
 #elif defined(USE_ARM_ASM)
-  return _gcry_aes_arm_encrypt_block(ctx->keyschenc, bx, ax, ctx->rounds, encT);
+  return _gcry_aes_arm_encrypt_block(ctx->keyschenc, bx, ax, ctx->rounds,
+				     enc_tables.T);
 #else
   return do_encrypt_fn (ctx, bx, ax);
 #endif /* !USE_ARM_ASM && !USE_AMD64_ASM*/
@@ -1129,10 +1150,10 @@
 {
 #ifdef USE_AMD64_ASM
   return _gcry_aes_amd64_decrypt_block(ctx->keyschdec, bx, ax, ctx->rounds,
-				       &dec_tables);
+				       dec_tables.T);
 #elif defined(USE_ARM_ASM)
   return _gcry_aes_arm_decrypt_block(ctx->keyschdec, bx, ax, ctx->rounds,
-				     &dec_tables);
+				     dec_tables.T);
 #else
   return do_decrypt_fn (ctx, bx, ax);
 #endif /*!USE_ARM_ASM && !USE_AMD64_ASM*/
```
