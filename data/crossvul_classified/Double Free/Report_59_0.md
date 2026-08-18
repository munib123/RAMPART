# CrossVul Fix Pair: Double Free in c
**Pair ID:** 59_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `59_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 2283-2323 of the vulnerable file.

      return (r);
    r = create_code(a, &rar->lengthcode,
                &rar->lengthtable[MAINCODE_SIZE + OFFSETCODE_SIZE +
                LOWOFFSETCODE_SIZE], LENGTHCODE_SIZE, MAX_SYMBOL_LENGTH);
    if (r != ARCHIVE_OK)
      return (r);
  }

  if (!rar->dictionary_size || !rar->lzss.window)
  {
    /* Seems as though dictionary sizes are not used. Even so, minimize
     * memory usage as much as possible.
     */
    void *new_window;
    unsigned int new_size;

    if (rar->unp_size >= DICTIONARY_MAX_SIZE)
      new_size = DICTIONARY_MAX_SIZE;
    else
      new_size = rar_fls((unsigned int)rar->unp_size) << 1;
    new_window = realloc(rar->lzss.window, new_size);
    if (new_window == NULL) {
      archive_set_error(&a->archive, ENOMEM,
                        "Unable to allocate memory for uncompressed data.");
      return (ARCHIVE_FATAL);
    }
    rar->lzss.window = (unsigned char *)new_window;
    rar->dictionary_size = new_size;
    memset(rar->lzss.window, 0, rar->dictionary_size);
    rar->lzss.mask = rar->dictionary_size - 1;
  }

  rar->start_new_table = 0;
  return (ARCHIVE_OK);
truncated_data:
  archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                    "Truncated RAR file data");
  rar->valid = 0;
  return (ARCHIVE_FATAL);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2300,6 +2300,11 @@
       new_size = DICTIONARY_MAX_SIZE;
     else
       new_size = rar_fls((unsigned int)rar->unp_size) << 1;
+    if (new_size == 0) {
+      archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+                        "Zero window size is invalid.");
+      return (ARCHIVE_FATAL);
+    }
     new_window = realloc(rar->lzss.window, new_size);
     if (new_window == NULL) {
       archive_set_error(&a->archive, ENOMEM,
```
