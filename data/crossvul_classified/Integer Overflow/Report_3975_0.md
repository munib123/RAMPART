# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 3975_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3975_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 77-119 of the vulnerable file.

    {"cnonce", DIGEST_CNONCE},
    {"response", DIGEST_RESPONSE},
    {nullptr, DIGEST_INVALID_ATTR}
};

LookupTable<http_digest_attr_type>
DigestFieldsLookupTable(DIGEST_INVALID_ATTR, DigestAttrs);

/*
 *
 * Nonce Functions
 *
 */

static void authenticateDigestNonceCacheCleanup(void *data);
static digest_nonce_h *authenticateDigestNonceFindNonce(const char *noncehex);
static void authenticateDigestNonceDelete(digest_nonce_h * nonce);
static void authenticateDigestNonceSetup(void);
static void authDigestNonceEncode(digest_nonce_h * nonce);
static void authDigestNonceLink(digest_nonce_h * nonce);
#if NOT_USED
static int authDigestNonceLinks(digest_nonce_h * nonce);
#endif
static void authDigestNonceUserUnlink(digest_nonce_h * nonce);

static void
authDigestNonceEncode(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (nonce->key)
        xfree(nonce->key);

    SquidMD5_CTX Md5Ctx;
    HASH H;
    SquidMD5Init(&Md5Ctx);
    SquidMD5Update(&Md5Ctx, reinterpret_cast<const uint8_t *>(&nonce->noncedata), sizeof(nonce->noncedata));
    SquidMD5Final(reinterpret_cast<uint8_t *>(H), &Md5Ctx);

    nonce->key = xcalloc(sizeof(HASHHEX), 1);
    CvtHex(H, static_cast<char *>(nonce->key));
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,9 +94,6 @@
 static void authenticateDigestNonceSetup(void);
 static void authDigestNonceEncode(digest_nonce_h * nonce);
 static void authDigestNonceLink(digest_nonce_h * nonce);
-#if NOT_USED
-static int authDigestNonceLinks(digest_nonce_h * nonce);
-#endif
 static void authDigestNonceUserUnlink(digest_nonce_h * nonce);
 
 static void
@@ -289,20 +286,9 @@
 {
     assert(nonce != NULL);
     ++nonce->references;
+    assert(nonce->references != 0); // no overflows
     debugs(29, 9, "nonce '" << nonce << "' now at '" << nonce->references << "'.");
 }
-
-#if NOT_USED
-static int
-authDigestNonceLinks(digest_nonce_h * nonce)
-{
-    if (!nonce)
-        return -1;
-
-    return nonce->references;
-}
-
-#endif
 
 void
 authDigestNonceUnlink(digest_nonce_h * nonce)
```
