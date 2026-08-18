# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4028_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4028_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 79-119 of the vulnerable file.

	ptr = (BYTE*)(*PublicKey);

	if (!ptr)
	{
		status = FALSE;
		goto exit;
	}

	i2d_PublicKey(pkey, &ptr);
exit:

	if (pkey)
		EVP_PKEY_free(pkey);

	return status;
}

static int crypto_rsa_common(const BYTE* input, int length, UINT32 key_length, const BYTE* modulus,
                             const BYTE* exponent, int exponent_size, BYTE* output)
{
	BN_CTX* ctx;
	int output_length = -1;
	BYTE* input_reverse;
	BYTE* modulus_reverse;
	BYTE* exponent_reverse;
	BIGNUM *mod, *exp, *x, *y;
	input_reverse = (BYTE*)malloc(2 * key_length + exponent_size);

	if (!input_reverse)
		return -1;

	modulus_reverse = input_reverse + key_length;
	exponent_reverse = modulus_reverse + key_length;
	memcpy(modulus_reverse, modulus, key_length);
	crypto_reverse(modulus_reverse, key_length);
	memcpy(exponent_reverse, exponent, exponent_size);
	crypto_reverse(exponent_reverse, exponent_size);
	memcpy(input_reverse, input, length);
	crypto_reverse(input_reverse, length);

	if (!(ctx = BN_CTX_new()))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,13 +96,24 @@
 static int crypto_rsa_common(const BYTE* input, int length, UINT32 key_length, const BYTE* modulus,
                              const BYTE* exponent, int exponent_size, BYTE* output)
 {
-	BN_CTX* ctx;
+	BN_CTX* ctx = NULL;
 	int output_length = -1;
-	BYTE* input_reverse;
-	BYTE* modulus_reverse;
-	BYTE* exponent_reverse;
-	BIGNUM *mod, *exp, *x, *y;
-	input_reverse = (BYTE*)malloc(2 * key_length + exponent_size);
+	BYTE* input_reverse = NULL;
+	BYTE* modulus_reverse = NULL;
+	BYTE* exponent_reverse = NULL;
+	BIGNUM* mod = NULL;
+	BIGNUM* exp = NULL;
+	BIGNUM* x = NULL;
+	BIGNUM* y = NULL;
+	size_t bufferSize = 2 * key_length + exponent_size;
+
+	if (!input || (length < 0) || (exponent_size < 0) || !modulus || !exponent || !output)
+		return -1;
+
+	if (length > bufferSize)
+		bufferSize = length;
+
+	input_reverse = (BYTE*)calloc(bufferSize, 1);
 
 	if (!input_reverse)
 		return -1;
@@ -131,16 +142,24 @@
 	if (!(y = BN_new()))
 		goto fail_bn_y;
 
-	BN_bin2bn(modulus_reverse, key_length, mod);
-	BN_bin2bn(exponent_reverse, exponent_size, exp);
-	BN_bin2bn(input_reverse, length, x);
-	BN_mod_exp(y, x, exp, mod, ctx);
+	if (!BN_bin2bn(modulus_reverse, key_length, mod))
+		goto fail;
+
+	if (!BN_bin2bn(exponent_reverse, exponent_size, exp))
+		goto fail;
+	if (!BN_bin2bn(input_reverse, length, x))
+		goto fail;
+	if (BN_mod_exp(y, x, exp, mod, ctx) != 1)
+		goto fail;
 	output_length = BN_bn2bin(y, output);
+	if (output_length < 0)
+		goto fail;
 	crypto_reverse(output, output_length);
 
-	if (output_length < (int)key_length)
+	if (output_length < key_length)
 		memset(output + output_length, 0, key_length - output_length);
 
+fail:
 	BN_free(y);
 fail_bn_y:
 	BN_clear_free(x);
```
