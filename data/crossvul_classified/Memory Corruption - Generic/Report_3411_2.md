# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3411_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3411_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 416-456 of the vulnerable file.

          fileblock -= grub_le_to_cpu32 (ext[i].block);
          if (fileblock >= grub_le_to_cpu16 (ext[i].len))
            return 0;
          else
            {
              grub_disk_addr_t start;

              start = grub_le_to_cpu16 (ext[i].start_hi);
              start = (start << 32) + grub_le_to_cpu32 (ext[i].start);

              return fileblock + start;
            }
        }
      else
        {
          grub_error (GRUB_ERR_BAD_FS, "something wrong with extent");
          return -1;
        }
    }
  /* Direct blocks.  */
  if (fileblock < INDIRECT_BLOCKS)
    blknr = grub_le_to_cpu32 (inode->blocks.dir_blocks[fileblock]);
  /* Indirect.  */
  else if (fileblock < INDIRECT_BLOCKS + blksz / 4)
    {
      grub_uint32_t *indir;

      indir = grub_malloc (blksz);
      if (! indir)
	return grub_errno;

      if (grub_disk_read (data->disk,
			  ((grub_disk_addr_t)
			   grub_le_to_cpu32 (inode->blocks.indir_block))
			  << log2_blksz,
			  0, blksz, indir))
	return grub_errno;

      blknr = grub_le_to_cpu32 (indir[fileblock - INDIRECT_BLOCKS]);
      grub_free (indir);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -433,10 +433,10 @@
         }
     }
   /* Direct blocks.  */
-  if (fileblock < INDIRECT_BLOCKS)
+  if (fileblock < INDIRECT_BLOCKS) {
     blknr = grub_le_to_cpu32 (inode->blocks.dir_blocks[fileblock]);
   /* Indirect.  */
-  else if (fileblock < INDIRECT_BLOCKS + blksz / 4)
+  } else if (fileblock < INDIRECT_BLOCKS + blksz / 4)
     {
       grub_uint32_t *indir;
 
@@ -680,23 +680,26 @@
 
       if (dirent.namelen != 0)
 	{
-#ifndef _MSC_VER
-	  char filename[dirent.namelen + 1]; 
-#else
 	  char * filename = grub_malloc (dirent.namelen + 1);
-#endif
 	  struct grub_fshelp_node *fdiro;
 	  enum grub_fshelp_filetype type = GRUB_FSHELP_UNKNOWN;
 
+if (!filename) {
+break;
+}
 	  grub_ext2_read_file (diro, 0, 0, 0,
 			       fpos + sizeof (struct ext2_dirent),
 			       dirent.namelen, filename);
-	  if (grub_errno)
+	  if (grub_errno) {
+            free (filename);
 	    return 0;
+	  }
 
 	  fdiro = grub_malloc (sizeof (struct grub_fshelp_node));
-	  if (! fdiro)
+	  if (! fdiro) {
+            free (filename);
 	    return 0;
+          }
 
 	  fdiro->data = diro->data;
 	  fdiro->ino = grub_le_to_cpu32 (dirent.inode);
@@ -721,8 +724,8 @@
 	      grub_ext2_read_inode (diro->data,
                                     grub_le_to_cpu32 (dirent.inode),
 				    &fdiro->inode);
-	      if (grub_errno)
-		{
+	      if (grub_errno) {
+                  free (filename);
 		  grub_free (fdiro);
 		  return 0;
 		}
@@ -740,8 +743,11 @@
 		type = GRUB_FSHELP_REG;
 	    }
 
-	  if (hook (filename, type, fdiro, closure))
+	  if (hook (filename, type, fdiro, closure)) {
+            free (filename);
 	    return 1;
+          }
+          free (filename);
 	}
 
       fpos += grub_le_to_cpu16 (dirent.direntlen);
```
