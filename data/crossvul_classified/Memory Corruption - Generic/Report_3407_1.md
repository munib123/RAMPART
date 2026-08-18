# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3407_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3407_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.

#define EXT2_PATH_MAX		4096
/* Maximum nesting of symlinks, used to prevent a loop.  */
#define	EXT2_MAX_SYMLINKCNT	8

/* The good old revision and the default inode size.  */
#define EXT2_GOOD_OLD_REVISION		0
#define EXT2_GOOD_OLD_INODE_SIZE	128

/* Filetype used in directory entry.  */
#define	FILETYPE_UNKNOWN	0
#define	FILETYPE_REG		1
#define	FILETYPE_DIRECTORY	2
#define	FILETYPE_SYMLINK	7

/* Filetype information as used in inodes.  */
#define FILETYPE_INO_MASK	0170000
#define FILETYPE_INO_REG	0100000
#define FILETYPE_INO_DIRECTORY	0040000
#define FILETYPE_INO_SYMLINK	0120000

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/fshelp.h>

/* Log2 size of ext2 block in 512 blocks.  */
#define LOG2_EXT2_BLOCK_SIZE(data)			\
	(grub_le_to_cpu32 (data->sblock.log2_block_size) + 1)

/* Log2 size of ext2 block in bytes.  */
#define LOG2_BLOCK_SIZE(data)					\
	(grub_le_to_cpu32 (data->sblock.log2_block_size) + 10)

/* The size of an ext2 block in bytes.  */
#define EXT2_BLOCK_SIZE(data)		(1 << LOG2_BLOCK_SIZE (data))

/* The revision level.  */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,6 +42,7 @@
 #define FILETYPE_INO_DIRECTORY	0040000
 #define FILETYPE_INO_SYMLINK	0120000
 
+#include <stdlib.h>
 #include <grub/err.h>
 #include <grub/file.h>
 #include <grub/mm.h>
@@ -368,8 +369,9 @@
       block = (block << 32) + grub_le_to_cpu32 (index[i].leaf);
       if (grub_disk_read (data->disk,
                           block << LOG2_EXT2_BLOCK_SIZE (data),
-                          0, EXT2_BLOCK_SIZE(data), buf))
+                          0, EXT2_BLOCK_SIZE(data), buf)) {
         return 0;
+      }
 
       ext_block = (struct grub_ext4_extent_header *) buf;
     }
@@ -386,11 +388,10 @@
 
   if (grub_le_to_cpu32(inode->flags) & EXT4_EXTENTS_FLAG)
     {
-#ifndef _MSC_VER
-	  char buf[EXT2_BLOCK_SIZE (data)];
-#else
-	  char * buf = grub_malloc (EXT2_BLOCK_SIZE(data));
-#endif
+	  char * buf = grub_malloc (EXT2_BLOCK_SIZE (data));
+          if (!buf) {
+              return -1;
+          }
       struct grub_ext4_extent_header *leaf;
       struct grub_ext4_extent *ext;
       int i;
@@ -401,6 +402,7 @@
       if (! leaf)
         {
           grub_error (GRUB_ERR_BAD_FS, "invalid extent");
+	  free (buf);
           return -1;
         }
 
@@ -414,14 +416,16 @@
       if (--i >= 0)
         {
           fileblock -= grub_le_to_cpu32 (ext[i].block);
-          if (fileblock >= grub_le_to_cpu16 (ext[i].len))
+          if (fileblock >= grub_le_to_cpu16 (ext[i].len)) {
+  	    free (buf);
             return 0;
-          else
+          } else
             {
               grub_disk_addr_t start;
 
               start = grub_le_to_cpu16 (ext[i].start_hi);
               start = (start << 32) + grub_le_to_cpu32 (ext[i].start);
+  	    free (buf);
 
               return fileblock + start;
             }
@@ -429,8 +433,10 @@
       else
         {
           grub_error (GRUB_ERR_BAD_FS, "something wrong with extent");
+  	    free (buf);
           return -1;
         }
+free (buf);
     }
   /* Direct blocks.  */
   if (fileblock < INDIRECT_BLOCKS) {
@@ -441,15 +447,17 @@
       grub_uint32_t *indir;
 
       indir = grub_malloc (blksz);
-      if (! indir)
+      if (! indir) {
 	return grub_errno;
+}
 
       if (grub_disk_read (data->disk,
 			  ((grub_disk_addr_t)
 			   grub_le_to_cpu32 (inode->blocks.indir_block))
 			  << log2_blksz,
-			  0, blksz, indir))
+			  0, blksz, indir)) {
 	return grub_errno;
+}
 
       blknr = grub_le_to_cpu32 (indir[fileblock - INDIRECT_BLOCKS]);
       grub_free (indir);
@@ -464,22 +472,25 @@
       grub_uint32_t *indir;
 
       indir = grub_malloc (blksz);
-      if (! indir)
+      if (! indir) {
 	return grub_errno;
+}
 
       if (grub_disk_read (data->disk,
 			  ((grub_disk_addr_t)
 			   grub_le_to_cpu32 (inode->blocks.double_indir_block))
 			  << log2_blksz,
-			  0, blksz, indir))
+			  0, blksz, indir)) {
 	return grub_errno;
+}
 
       if (grub_disk_read (data->disk,
 			  ((grub_disk_addr_t)
 			   grub_le_to_cpu32 (indir[rblock / perblock]))
 			  << log2_blksz,
-			  0, blksz, indir))
+			  0, blksz, indir)) {
 	return grub_errno;
+}
 
       blknr = grub_le_to_cpu32 (indir[rblock % perblock]);
             grub_free (indir);
```
