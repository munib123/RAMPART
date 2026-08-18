# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3407_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3407_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_io.h>
#include <r_fs.h>
#include "grubfs.h"
#include <stdio.h>
#include <string.h>


static RIOBind *bio = NULL;
static ut64 delta = 0;

static void* empty (int sz) {
	void *p = malloc (sz);
	if (p) memset (p, '\0', sz);
	return p;
}

static grub_err_t read_foo (struct grub_disk *disk, grub_disk_addr_t sector, grub_size_t size, char *buf) {
	if (disk != NULL) {
		const int blocksize = 512; // unhardcode 512
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */
+/* radare - LGPL - Copyright 2011-2017 pancake<nopcode.org> */
 
 #include <r_io.h>
 #include <r_fs.h>
@@ -17,20 +17,20 @@
 }
 
 static grub_err_t read_foo (struct grub_disk *disk, grub_disk_addr_t sector, grub_size_t size, char *buf) {
-	if (disk != NULL) {
-		const int blocksize = 512; // unhardcode 512
-		int ret;
-		RIOBind *iob = disk->data;
-		if (bio) iob = bio;
-		//printf ("io %p\n", file->root->iob.io);
-		ret = iob->read_at (iob->io, delta+(blocksize*sector),
-			(ut8*)buf, size*blocksize);
-		if (ret == -1)
-			return 1;
-		//printf ("DISK PTR = %p\n", disk->data);
-		//printf ("\nBUF: %x %x %x %x\n", buf[0], buf[1], buf[2], buf[3]);
-	} else eprintf ("oops. no disk\n");
-	return 0; // 0 is ok
+	if (!disk) {
+		eprintf ("oops. no disk\n");
+		return 1;
+	}
+	const int blocksize = 512; // TODO unhardcode 512
+	RIOBind *iob = disk->data;
+	if (bio) {
+		iob = bio;
+	}
+	//printf ("io %p\n", file->root->iob.io);
+	if (iob->read_at (iob->io, delta+(blocksize*sector), (ut8*)buf, size*blocksize) == -1) {
+		return 1;
+	}
+	return 0;
 }
 
 GrubFS *grubfs_new (struct grub_fs *myfs, void *data) {
@@ -58,8 +58,9 @@
 
 void grubfs_free (GrubFS *gf) {
 	if (gf) {
-		if (gf->file && gf->file->device)
+		if (gf->file && gf->file->device) {
 			free (gf->file->device->disk);
+		}
 		//free (gf->file->device);
 		free (gf->file);
 		free (gf);
```
