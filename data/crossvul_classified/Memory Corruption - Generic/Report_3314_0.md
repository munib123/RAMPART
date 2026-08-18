# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3314_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3314_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 28-68 of the vulnerable file.

};

struct crypto_ccm_ctx {
	struct crypto_ahash *mac;
	struct crypto_skcipher *ctr;
};

struct crypto_rfc4309_ctx {
	struct crypto_aead *child;
	u8 nonce[3];
};

struct crypto_rfc4309_req_ctx {
	struct scatterlist src[3];
	struct scatterlist dst[3];
	struct aead_request subreq;
};

struct crypto_ccm_req_priv_ctx {
	u8 odata[16];
	u8 auth_tag[16];
	u32 flags;
	struct scatterlist src[3];
	struct scatterlist dst[3];
	struct skcipher_request skreq;
};

struct cbcmac_tfm_ctx {
	struct crypto_cipher *child;
};

struct cbcmac_desc_ctx {
	unsigned int len;
};

static inline struct crypto_ccm_req_priv_ctx *crypto_ccm_reqctx(
	struct aead_request *req)
{
	unsigned long align = crypto_aead_alignmask(crypto_aead_reqtfm(req));

	return (void *)PTR_ALIGN((u8 *)aead_request_ctx(req), align + 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,6 +45,7 @@
 
 struct crypto_ccm_req_priv_ctx {
 	u8 odata[16];
+	u8 idata[16];
 	u8 auth_tag[16];
 	u32 flags;
 	struct scatterlist src[3];
@@ -183,8 +184,8 @@
 	AHASH_REQUEST_ON_STACK(ahreq, ctx->mac);
 	unsigned int assoclen = req->assoclen;
 	struct scatterlist sg[3];
-	u8 odata[16];
-	u8 idata[16];
+	u8 *odata = pctx->odata;
+	u8 *idata = pctx->idata;
 	int ilen, err;
 
 	/* format control data for input */
```
