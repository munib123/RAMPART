# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3071_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3071_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 67-110 of the vulnerable file.

/*
 * What's the address length associated with this AFI?
 */
static int length_from_afi(const unsigned afi)
{
    switch (afi) {
    case IANA_AFI_IPV4:
        return 4;
    case IANA_AFI_IPV6:
        return 16;
    default:
        return 0;
    }
}

/*
 * Extract the AFI from an IPAddressFamily.
 */
unsigned int X509v3_addr_get_afi(const IPAddressFamily *f)
{
    return ((f != NULL &&
             f->addressFamily != NULL && f->addressFamily->data != NULL)
            ? ((f->addressFamily->data[0] << 8) | (f->addressFamily->data[1]))
            : 0);
}

/*
 * Expand the bitstring form of an address into a raw byte array.
 * At the moment this is coded for simplicity, not speed.
 */
static int addr_expand(unsigned char *addr,
                       const ASN1_BIT_STRING *bs,
                       const int length, const unsigned char fill)
{
    if (bs->length < 0 || bs->length > length)
        return 0;
    if (bs->length > 0) {
        memcpy(addr, bs->data, bs->length);
        if ((bs->flags & 7) != 0) {
            unsigned char mask = 0xFF >> (8 - (bs->flags & 7));
            if (fill == 0)
                addr[bs->length - 1] &= ~mask;
            else
                addr[bs->length - 1] |= mask;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,10 +84,12 @@
  */
 unsigned int X509v3_addr_get_afi(const IPAddressFamily *f)
 {
-    return ((f != NULL &&
-             f->addressFamily != NULL && f->addressFamily->data != NULL)
-            ? ((f->addressFamily->data[0] << 8) | (f->addressFamily->data[1]))
-            : 0);
+    if (f == NULL
+            || f->addressFamily == NULL
+            || f->addressFamily->data == NULL
+            || f->addressFamily->length < 2)
+        return 0;
+    return (f->addressFamily->data[0] << 8) | f->addressFamily->data[1];
 }
 
 /*
```
