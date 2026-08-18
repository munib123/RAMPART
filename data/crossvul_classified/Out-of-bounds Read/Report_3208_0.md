# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3208_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3208_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1130-1170 of the vulnerable file.

      TNEF->IO.CloseProc(&TNEF->IO);
    }
    return YTNEF_NOT_TNEF_STREAM;
  }

  DEBUG(TNEF->Debug, 2, "Reading Key.");

  if (TNEFGetKey(TNEF, &key) < 0) {
    printf("ERROR: Unable to retrieve key.\n");
    if (TNEF->IO.CloseProc != NULL) {
      TNEF->IO.CloseProc(&TNEF->IO);
    }
    return YTNEF_NO_KEY;
  }

  DEBUG(TNEF->Debug, 2, "Starting Full Processing.");

  while (TNEFGetHeader(TNEF, &type, &size) == 0) {
    DEBUG2(TNEF->Debug, 2, "Header says type=0x%X, size=%u", type, size);
    DEBUG2(TNEF->Debug, 2, "Header says type=%u, size=%u", type, size);
    data = calloc(size, sizeof(BYTE));
    ALLOCCHECK(data);
    if (TNEFRawRead(TNEF, data, size, &header_checksum) < 0) {
      printf("ERROR: Unable to read data.\n");
      if (TNEF->IO.CloseProc != NULL) {
        TNEF->IO.CloseProc(&TNEF->IO);
      }
      free(data);
      return YTNEF_ERROR_READING_DATA;
    }
    if (TNEFRawRead(TNEF, (BYTE *)&checksum, 2, NULL) < 0) {
      printf("ERROR: Unable to read checksum.\n");
      if (TNEF->IO.CloseProc != NULL) {
        TNEF->IO.CloseProc(&TNEF->IO);
      }
      free(data);
      return YTNEF_ERROR_READING_DATA;
    }
    checksum = SwapWord((BYTE *)&checksum, sizeof(WORD));
    if (checksum != header_checksum) {
      printf("ERROR: Checksum mismatch. Data corruption?:\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1147,6 +1147,10 @@
   while (TNEFGetHeader(TNEF, &type, &size) == 0) {
     DEBUG2(TNEF->Debug, 2, "Header says type=0x%X, size=%u", type, size);
     DEBUG2(TNEF->Debug, 2, "Header says type=%u, size=%u", type, size);
+    if(size == 0) {
+      printf("ERROR: Field with size of 0\n");
+      return YTNEF_ERROR_READING_DATA;
+    }
     data = calloc(size, sizeof(BYTE));
     ALLOCCHECK(data);
     if (TNEFRawRead(TNEF, data, size, &header_checksum) < 0) {
```
