# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3207_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3207_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1373-1413 of the vulnerable file.

      mapidata = &(mapi->data[i]);
      if (mapi->count > 1) {
        printf("    [%i/%u] ", i, mapi->count);
      } else {
        printf("    ");
      }
      printf("Size: %i", mapidata->size);
      switch (PROP_TYPE(mapi->id)) {
        case PT_SYSTIME:
          MAPISysTimetoDTR(mapidata->data, &thedate);
          printf("    Value: ");
          ddword_tmp = *((DDWORD *)mapidata->data);
          TNEFPrintDate(thedate);
          printf(" [HEX: ");
          for (x = 0; x < sizeof(ddword_tmp); x++) {
            printf(" %02x", (BYTE)mapidata->data[x]);
          }
          printf("] (%llu)\n", ddword_tmp);
          break;
        case PT_LONG:
          printf("    Value: %li\n", *((long*)mapidata->data));
          break;
        case PT_I2:
          printf("    Value: %hi\n", *((short int*)mapidata->data));
          break;
        case PT_BOOLEAN:
          if (mapi->data->data[0] != 0) {
            printf("    Value: True\n");
          } else {
            printf("    Value: False\n");
          }
          break;
        case PT_OBJECT:
          printf("\n");
          break;
        case PT_BINARY:
          if (IsCompressedRTF(mapidata) == 1) {
            printf("    Detected Compressed RTF. ");
            printf("Decompressed text follows\n");
            printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
            if ((vlTemp.data = (BYTE*)DecompressRTF(mapidata, &(vlTemp.size))) != NULL) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1390,7 +1390,7 @@
           printf("] (%llu)\n", ddword_tmp);
           break;
         case PT_LONG:
-          printf("    Value: %li\n", *((long*)mapidata->data));
+          printf("    Value: %i\n", *((int*)mapidata->data));
           break;
         case PT_I2:
           printf("    Value: %hi\n", *((short int*)mapidata->data));
```
