# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1063_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1063_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 553-594 of the vulnerable file.

			 taglen, len);
		return NULL;
	}
	*buflen -= (p - *buf) + taglen;
	*buf = p + taglen;	/* point to next tag */
	*taglen_out = taglen;
	return p;
}

const u8 *sc_asn1_verify_tag(sc_context_t *ctx, const u8 * buf, size_t buflen,
			     unsigned int tag_in, size_t *taglen_out)
{
	return sc_asn1_skip_tag(ctx, &buf, &buflen, tag_in, taglen_out);
}

static int decode_bit_string(const u8 * inbuf, size_t inlen, void *outbuf,
			     size_t outlen, int invert)
{
	const u8 *in = inbuf;
	u8 *out = (u8 *) outbuf;
	int zero_bits = *in & 0x07;
	size_t octets_left = inlen - 1;
	int i, count = 0;

	memset(outbuf, 0, outlen);
	in++;
	if (outlen < octets_left)
		return SC_ERROR_BUFFER_TOO_SMALL;
	if (inlen < 1)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	while (octets_left) {
		/* 1st octet of input:  ABCDEFGH, where A is the MSB */
		/* 1st octet of output: HGFEDCBA, where A is the LSB */
		/* first bit in bit string is the LSB in first resulting octet */
		int bits_to_go;

		*out = 0;
		if (octets_left == 1)
			bits_to_go = 8 - zero_bits;
		else
			bits_to_go = 8;
		if (invert)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -570,16 +570,20 @@
 {
 	const u8 *in = inbuf;
 	u8 *out = (u8 *) outbuf;
-	int zero_bits = *in & 0x07;
-	size_t octets_left = inlen - 1;
 	int i, count = 0;
-
-	memset(outbuf, 0, outlen);
-	in++;
+	int zero_bits;
+	size_t octets_left;
+
 	if (outlen < octets_left)
 		return SC_ERROR_BUFFER_TOO_SMALL;
 	if (inlen < 1)
 		return SC_ERROR_INVALID_ASN1_OBJECT;
+
+	zero_bits = *in & 0x07;
+	octets_left = inlen - 1;
+	in++;
+	memset(outbuf, 0, outlen);
+
 	while (octets_left) {
 		/* 1st octet of input:  ABCDEFGH, where A is the MSB */
 		/* 1st octet of output: HGFEDCBA, where A is the LSB */
```
