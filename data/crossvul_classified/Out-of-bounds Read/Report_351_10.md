# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_10
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_10`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1044-1084 of the vulnerable file.

static int
pgp_enumerate_blob(sc_card_t *card, pgp_blob_t *blob)
{
	const u8	*in;
	int		r;

	if (blob->files != NULL)
		return SC_SUCCESS;

	if ((r = pgp_read_blob(card, blob)) < 0)
		return r;

	in = blob->data;

	while ((int) blob->len > (in - blob->data)) {
		unsigned int	cla, tag, tmptag;
		size_t		len;
		const u8	*data = in;
		pgp_blob_t	*new;

		r = sc_asn1_read_tag(&data, blob->len - (in - blob->data),
					&cla, &tag, &len);
		if (r < 0 || data == NULL) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				 "Unexpected end of contents\n");
			return SC_ERROR_OBJECT_NOT_VALID;
		}

		/* undo ASN1's split of tag & class */
		for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {
			cla <<= 8;
		}
		tag |= cla;

		/* Awful hack for composite DOs that have
		 * a TLV with the DO's id encompassing the
		 * entire blob. Example: Yubikey Neo */
		if (tag == blob->id) {
			in = data;
			continue;
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1061,6 +1061,9 @@
 		const u8	*data = in;
 		pgp_blob_t	*new;
 
+		if (!in)
+			return SC_ERROR_OBJECT_NOT_VALID;
+
 		r = sc_asn1_read_tag(&data, blob->len - (in - blob->data),
 					&cla, &tag, &len);
 		if (r < 0 || data == NULL) {
@@ -1068,6 +1071,9 @@
 				 "Unexpected end of contents\n");
 			return SC_ERROR_OBJECT_NOT_VALID;
 		}
+
+		if (data + len > blob->data + blob->len)
+			return SC_ERROR_OBJECT_NOT_VALID;
 
 		/* undo ASN1's split of tag & class */
 		for (tmptag = tag; tmptag > 0x0FF; tmptag >>= 8) {
```
