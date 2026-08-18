# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 734_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `734_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 466-518 of the vulnerable file.

        sys->message(fh, "invalid section number '%u'.", section);
        continue;
      }

      if (!(fi = (struct mschmd_file *) sys->alloc(sys, sizeof(struct mschmd_file) + name_len + 1))) {
        sys->free(chunk);
        return MSPACK_ERR_NOMEMORY;
      }

      fi->next     = NULL;
      fi->filename = (char *) &fi[1];
      fi->section  = ((section == 0) ? (struct mschmd_section *) (&chm->sec0)
                                     : (struct mschmd_section *) (&chm->sec1));
      fi->offset   = offset;
      fi->length   = length;
      sys->copy(name, fi->filename, (size_t) name_len);
      fi->filename[name_len] = '\0';

      if (name[0] == ':' && name[1] == ':') {
        /* system file */
        if (memcmp(&name[2], &content_name[2], 31L) == 0) {
          if (memcmp(&name[33], &content_name[33], 8L) == 0) {
            chm->sec1.content = fi;
          }
          else if (memcmp(&name[33], &control_name[33], 11L) == 0) {
            chm->sec1.control = fi;
          }
          else if (memcmp(&name[33], &spaninfo_name[33], 8L) == 0) {
            chm->sec1.spaninfo = fi;
          }
          else if (memcmp(&name[33], &rtable_name[33], 72L) == 0) {
            chm->sec1.rtable = fi;
          }
        }
        fi->next = chm->sysfiles;
        chm->sysfiles = fi;
      }
      else {
        /* normal file */
        if (link) link->next = fi; else chm->files = fi;
        link = fi;
      }
    }

    /* this is reached either when num_entries runs out, or if
     * reading data from the chunk reached a premature end of chunk */
  chunk_end:
    if (num_entries >= 0) {
      D(("chunk ended before all entries could be read"))
      errors++;
    }

  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -483,19 +483,17 @@
 
       if (name[0] == ':' && name[1] == ':') {
         /* system file */
-        if (memcmp(&name[2], &content_name[2], 31L) == 0) {
-          if (memcmp(&name[33], &content_name[33], 8L) == 0) {
-            chm->sec1.content = fi;
-          }
-          else if (memcmp(&name[33], &control_name[33], 11L) == 0) {
-            chm->sec1.control = fi;
-          }
-          else if (memcmp(&name[33], &spaninfo_name[33], 8L) == 0) {
-            chm->sec1.spaninfo = fi;
-          }
-          else if (memcmp(&name[33], &rtable_name[33], 72L) == 0) {
-            chm->sec1.rtable = fi;
-          }
+        if (name_len == 40 && memcmp(name, content_name, 40) == 0) {
+          chm->sec1.content = fi;
+        }
+        else if (name_len == 44 && memcmp(name, control_name, 44) == 0) {
+          chm->sec1.control = fi;
+        }
+        else if (name_len == 41 && memcmp(name, spaninfo_name, 41) == 0) {
+          chm->sec1.spaninfo = fi;
+        }
+        else if (name_len == 105 && memcmp(name, rtable_name, 105) == 0) {
+          chm->sec1.rtable = fi;
         }
         fi->next = chm->sysfiles;
         chm->sysfiles = fi;
```
