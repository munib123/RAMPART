# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 60_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `60_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 241-281 of the vulnerable file.

  /* Fields to help with tracking decompression of files. */
  int64_t bytes_unconsumed;
  int64_t bytes_remaining;
  int64_t bytes_uncopied;
  int64_t offset;
  int64_t offset_outgoing;
  int64_t offset_seek;
  char valid;
  unsigned int unp_offset;
  unsigned int unp_buffer_size;
  unsigned char *unp_buffer;
  unsigned int dictionary_size;
  char start_new_block;
  char entry_eof;
  unsigned long crc_calculated;
  int found_first_header;
  char has_endarc_header;
  struct data_block_offsets *dbo;
  unsigned int cursor;
  unsigned int nodes;

  /* LZSS members */
  struct huffman_code maincode;
  struct huffman_code offsetcode;
  struct huffman_code lowoffsetcode;
  struct huffman_code lengthcode;
  unsigned char lengthtable[HUFFMAN_TABLE_SIZE];
  struct lzss lzss;
  char output_last_match;
  unsigned int lastlength;
  unsigned int lastoffset;
  unsigned int oldoffset[4];
  unsigned int lastlowoffset;
  unsigned int numlowoffsetrepeats;
  int64_t filterstart;
  char start_new_table;

  /* PPMd Variant H members */
  char ppmd_valid;
  char ppmd_eod;
  char is_ppmd_block;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -258,6 +258,7 @@
   struct data_block_offsets *dbo;
   unsigned int cursor;
   unsigned int nodes;
+  char filename_must_match;
 
   /* LZSS members */
   struct huffman_code maincode;
@@ -1560,6 +1561,12 @@
     }
     return ret;
   }
+  else if (rar->filename_must_match)
+  {
+    archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
+      "Mismatch of file parts split across multi-volume archive");
+    return (ARCHIVE_FATAL);
+  }
 
   rar->filename_save = (char*)realloc(rar->filename_save,
                                       filename_size + 1);
@@ -2933,12 +2940,14 @@
     else if (*avail == 0 && rar->main_flags & MHD_VOLUME &&
       rar->file_flags & FHD_SPLIT_AFTER)
     {
+      rar->filename_must_match = 1;
       ret = archive_read_format_rar_read_header(a, a->entry);
       if (ret == (ARCHIVE_EOF))
       {
         rar->has_endarc_header = 1;
         ret = archive_read_format_rar_read_header(a, a->entry);
       }
+      rar->filename_must_match = 0;
       if (ret != (ARCHIVE_OK))
         return NULL;
       return rar_read_ahead(a, min, avail);
```
