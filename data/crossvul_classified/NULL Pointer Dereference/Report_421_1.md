# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 421_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `421_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 430-471 of the vulnerable file.


    /* process only directory (PMGL) chunks */
    if (EndGetI32(&chunk[pmgl_Signature]) != 0x4C474D50) continue;

    if (EndGetI32(&chunk[pmgl_QuickRefSize]) < 2) {
      sys->message(fh, "WARNING; PMGL quickref area is too small");
    }
    if (EndGetI32(&chunk[pmgl_QuickRefSize]) > 
	((int)chm->chunk_size - pmgl_Entries))
    {
      sys->message(fh, "WARNING; PMGL quickref area is too large");
    }

    p = &chunk[pmgl_Entries];
    end = &chunk[chm->chunk_size - 2];
    num_entries = EndGetI16(end);

    while (num_entries--) {
      READ_ENCINT(name_len);
      if (name_len > (unsigned int) (end - p)) goto chunk_end;
      /* consider blank filenames to be an error */
      if (name_len == 0) goto chunk_end;
      name = p; p += name_len;

      READ_ENCINT(section);
      READ_ENCINT(offset);
      READ_ENCINT(length);

      /* empty files and directory names are stored as a file entry at
       * offset 0 with length 0. We want to keep empty files, but not
       * directory names, which end with a "/" */
      if ((offset == 0) && (length == 0)) {
	if ((name_len > 0) && (name[name_len-1] == '/')) continue;
      }

      if (section > 1) {
	sys->message(fh, "invalid section number '%u'.", section);
	continue;
      }

      if (!(fi = (struct mschmd_file *) sys->alloc(sys, sizeof(struct mschmd_file) + name_len + 1))) {
	sys->free(chunk);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -447,13 +447,13 @@
     while (num_entries--) {
       READ_ENCINT(name_len);
       if (name_len > (unsigned int) (end - p)) goto chunk_end;
-      /* consider blank filenames to be an error */
-      if (name_len == 0) goto chunk_end;
       name = p; p += name_len;
-
       READ_ENCINT(section);
       READ_ENCINT(offset);
       READ_ENCINT(length);
+
+      /* ignore blank or one-char (e.g. "/") filenames we'd return as blank */
+      if (name_len < 2 || !name[0] || !name[1]) continue;
 
       /* empty files and directory names are stored as a file entry at
        * offset 0 with length 0. We want to keep empty files, but not
```
