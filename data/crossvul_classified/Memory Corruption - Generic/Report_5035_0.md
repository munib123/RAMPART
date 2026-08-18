# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5035_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5035_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2110-2150 of the vulnerable file.

      if(maxorder > 16)
        maxorder = 16 + (maxorder - 16) * 3;

      if (maxorder == 1)
      {
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                          "Truncated RAR file data");
        return (ARCHIVE_FATAL);
      }

      /* Make sure ppmd7_contest is freed before Ppmd7_Construct
       * because reading a broken file cause this abnormal sequence. */
      __archive_ppmd7_functions.Ppmd7_Free(&rar->ppmd7_context, &g_szalloc);

      rar->bytein.a = a;
      rar->bytein.Read = &ppmd_read;
      __archive_ppmd7_functions.PpmdRAR_RangeDec_CreateVTable(&rar->range_dec);
      rar->range_dec.Stream = &rar->bytein;
      __archive_ppmd7_functions.Ppmd7_Construct(&rar->ppmd7_context);

      if (!__archive_ppmd7_functions.Ppmd7_Alloc(&rar->ppmd7_context,
        rar->dictionary_size, &g_szalloc))
      {
        archive_set_error(&a->archive, ENOMEM,
                          "Out of memory");
        return (ARCHIVE_FATAL);
      }
      if (!__archive_ppmd7_functions.PpmdRAR_RangeDec_Init(&rar->range_dec))
      {
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                          "Unable to initialize PPMd range decoder");
        return (ARCHIVE_FATAL);
      }
      __archive_ppmd7_functions.Ppmd7_Init(&rar->ppmd7_context, maxorder);
      rar->ppmd_valid = 1;
    }
    else
    {
      if (!rar->ppmd_valid) {
        archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                          "Invalid PPMd sequence");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2127,6 +2127,12 @@
       rar->range_dec.Stream = &rar->bytein;
       __archive_ppmd7_functions.Ppmd7_Construct(&rar->ppmd7_context);
 
+      if (rar->dictionary_size == 0) {
+	      archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+                          "Invalid zero dictionary size");
+	      return (ARCHIVE_FATAL);
+      }
+
       if (!__archive_ppmd7_functions.Ppmd7_Alloc(&rar->ppmd7_context,
         rar->dictionary_size, &g_szalloc))
       {
```
