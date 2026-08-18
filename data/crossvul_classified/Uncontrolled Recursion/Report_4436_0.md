# CrossVul Fix Pair: Uncontrolled Recursion in c
**Pair ID:** 4436_0
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4436_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```c
Lines 339-379 of the vulnerable file.


        insert_byte(buf, t->asn1class | t->construction | 0x1F);
    }

    return 0;
}

/*
 * Read a BER tag and length from asn1/len.  Place the tag parameters in
 * tag_out.  Set contents_out/clen_out to the octet range of the tag's
 * contents, and remainder_out/rlen_out to the octet range after the end of the
 * BER encoding.
 *
 * (krb5 ASN.1 encodings should be in DER, but for compatibility with some
 * really ancient implementations we handle the indefinite length form in tags.
 * However, we still insist on the primitive form of string types.)
 */
static krb5_error_code
get_tag(const uint8_t *asn1, size_t len, taginfo *tag_out,
        const uint8_t **contents_out, size_t *clen_out,
        const uint8_t **remainder_out, size_t *rlen_out)
{
    krb5_error_code ret;
    uint8_t o;
    const uint8_t *c, *p, *tag_start = asn1;
    size_t clen, llen, i;
    taginfo t;

    *contents_out = *remainder_out = NULL;
    *clen_out = *rlen_out = 0;
    if (len == 0)
        return ASN1_OVERRUN;
    o = *asn1++;
    len--;
    tag_out->asn1class = o & 0xC0;
    tag_out->construction = o & 0x20;
    if ((o & 0x1F) != 0x1F) {
        tag_out->tagnum = o & 0x1F;
    } else {
        tag_out->tagnum = 0;
        do {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -356,7 +356,7 @@
 static krb5_error_code
 get_tag(const uint8_t *asn1, size_t len, taginfo *tag_out,
         const uint8_t **contents_out, size_t *clen_out,
-        const uint8_t **remainder_out, size_t *rlen_out)
+        const uint8_t **remainder_out, size_t *rlen_out, int recursion)
 {
     krb5_error_code ret;
     uint8_t o;
@@ -394,9 +394,11 @@
         /* Indefinite form (should not be present in DER, but we accept it). */
         if (tag_out->construction != CONSTRUCTED)
             return ASN1_MISMATCH_INDEF;
+        if (recursion >= 32)
+            return ASN1_OVERFLOW;
         p = asn1;
         while (!(len >= 2 && p[0] == 0 && p[1] == 0)) {
-            ret = get_tag(p, len, &t, &c, &clen, &p, &len);
+            ret = get_tag(p, len, &t, &c, &clen, &p, &len, recursion + 1);
             if (ret)
                 return ret;
         }
@@ -613,7 +615,7 @@
     const uint8_t *contents, *remainder;
     size_t clen, rlen;
 
-    ret = get_tag(*der, len, tag_out, &contents, &clen, &remainder, &rlen);
+    ret = get_tag(*der, len, tag_out, &contents, &clen, &remainder, &rlen, 0);
     if (ret)
         return ret;
     if (rlen != 0)
@@ -1199,7 +1201,7 @@
         const uint8_t *rem;
         size_t rlen;
         if (!tag->implicit) {
-            ret = get_tag(asn1, len, &inner_tag, &asn1, &len, &rem, &rlen);
+            ret = get_tag(asn1, len, &inner_tag, &asn1, &len, &rem, &rlen, 0);
             if (ret)
                 return ret;
             /* Note: we don't check rlen (it should be 0). */
@@ -1420,7 +1422,7 @@
     for (i = 0; i < seq->n_fields; i++) {
         if (len == 0)
             break;
-        ret = get_tag(asn1, len, &t, &contents, &clen, &asn1, &len);
+        ret = get_tag(asn1, len, &t, &contents, &clen, &asn1, &len, 0);
         if (ret)
             goto error;
         /*
@@ -1478,7 +1480,7 @@
     *seq_out = NULL;
     *count_out = 0;
     while (len > 0) {
-        ret = get_tag(asn1, len, &t, &contents, &clen, &asn1, &len);
+        ret = get_tag(asn1, len, &t, &contents, &clen, &asn1, &len, 0);
         if (ret)
             goto error;
         if (!check_atype_tag(elemtype, &t)) {
@@ -1584,7 +1586,7 @@
 
     *retrep = NULL;
     ret = get_tag((uint8_t *)code->data, code->length, &t, &contents,
-                  &clen, &remainder, &rlen);
+                  &clen, &remainder, &rlen, 0);
     if (ret)
         return ret;
     /* rlen should be 0, but we don't check it (and due to padding in
```
