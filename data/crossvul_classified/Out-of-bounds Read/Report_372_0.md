# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 372_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `372_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 601-641 of the vulnerable file.

      if (BSON_UNLIKELY ((iter->raw + iter->d2)[l - 1] != '\0')) {
         iter->err_off = o + 4 + l - 1;
         goto mark_invalid;
      }
   } break;
   case BSON_TYPE_BINARY: {
      bson_subtype_t subtype;
      uint32_t l;

      if (o >= (len - 4)) {
         iter->err_off = o;
         goto mark_invalid;
      }

      iter->d2 = o + 4;
      iter->d3 = o + 5;

      memcpy (&l, iter->raw + iter->d1, sizeof (l));
      l = BSON_UINT32_FROM_LE (l);

      if (l >= (len - o)) {
         iter->err_off = o;
         goto mark_invalid;
      }

      subtype = *(iter->raw + iter->d2);

      if (subtype == BSON_SUBTYPE_BINARY_DEPRECATED) {
         int32_t binary_len;

         if (l < 4) {
            iter->err_off = o;
            goto mark_invalid;
         }

         /* subtype 2 has a redundant length header in the data */
         memcpy (&binary_len, (iter->raw + iter->d3), sizeof (binary_len));
         binary_len = BSON_UINT32_FROM_LE (binary_len);
         if (binary_len + 4 != l) {
            iter->err_off = iter->d3;
            goto mark_invalid;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -618,7 +618,7 @@
       memcpy (&l, iter->raw + iter->d1, sizeof (l));
       l = BSON_UINT32_FROM_LE (l);
 
-      if (l >= (len - o)) {
+      if (l >= (len - o - 4)) {
          iter->err_off = o;
          goto mark_invalid;
       }
```
