# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 502_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `502_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* radare - LGPL - Copyright 2010-2016 - nibble, pancake  */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "dyldcache.h"

static int r_bin_dyldcache_init(struct r_bin_dyldcache_obj_t* bin) {
	int len = r_buf_fread_at (bin->b, 0, (ut8*)&bin->hdr, "16c4i7l", 1);
	if (len == -1) {
		perror ("read (cache_header)");
		return false;
	}
	bin->nlibs = bin->hdr.numlibs;
	return true;
}

static int r_bin_dyldcache_apply_patch (struct r_buf_t* buf, ut32 data, ut64 offset) {
	return r_buf_write_at (buf, offset, (ut8*)&data, sizeof (data));
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* radare - LGPL - Copyright 2010-2016 - nibble, pancake  */
+/* radare - LGPL - Copyright 2010-2018 - nibble, pancake  */
 
 #include <stdio.h>
 #include <r_types.h>
@@ -20,6 +20,23 @@
 }
 
 #define NZ_OFFSET(x) if((x) > 0) r_bin_dyldcache_apply_patch (dbuf, (x) - linkedit_offset, (ut64)((size_t)&(x) - (size_t)data))
+
+// make it public in util/buf.c ?
+static ut64 r_buf_read64le (RBuffer *buf, ut64 off) {
+	ut8 data[8] = {0};
+	r_buf_read_at (buf, off, data, 8);
+	return r_read_le64 (data);
+}
+
+static char *r_buf_read_string (RBuffer *buf, ut64 addr, int len) {
+	ut8 *data = malloc (len);
+	if (data) {
+		r_buf_read_at (buf, addr, data, len);
+		data[len-1] = 0;
+		return data;
+	}
+	return NULL;
+}
 
 /* TODO: Needs more testing and ERROR HANDLING */
 struct r_bin_dyldcache_lib_t *r_bin_dyldcache_extract(struct r_bin_dyldcache_obj_t* bin, int idx, int *nlib) {
@@ -47,7 +64,6 @@
 	*nlib = bin->nlibs;
 	ret = R_NEW0 (struct r_bin_dyldcache_lib_t);
 	if (!ret) {
-		perror ("malloc (ret)");
 		return NULL;
 	}
 	if (bin->hdr.startaddr > bin->size) {
@@ -55,13 +71,20 @@
 		free (ret);
 		return NULL;
 	}
+
 	if (bin->hdr.startaddr > bin->size || bin->hdr.baseaddroff > bin->size) {
 		eprintf ("corrupted dyldcache");
 		free (ret);
 		return NULL;
 	}
-	image_infos = (struct dyld_cache_image_info*) (bin->b->buf + bin->hdr.startaddr);
-	dyld_vmbase = *(ut64 *)(bin->b->buf + bin->hdr.baseaddroff);
+	int sz = bin->nlibs * sizeof (struct dyld_cache_image_info);
+	image_infos = malloc (sz); //(struct dyld_cache_image_info*) (bin->b->buf + bin->hdr.startaddr);
+	if (!image_infos) {
+		free (ret);
+		return NULL;
+	}
+	r_buf_read_at (bin->b, bin->hdr.startaddr, (ut8*)image_infos, sz);
+	dyld_vmbase = r_buf_read64le (bin->b, bin->hdr.baseaddroff);
 	liboff = image_infos[idx].address - dyld_vmbase;
 	if (liboff > bin->size) {
 		eprintf ("Corrupted file\n");
@@ -69,12 +92,13 @@
 		return NULL;
 	}
 	ret->offset = liboff;
-	if (image_infos[idx].pathFileOffset > bin->size) {
-	    eprintf ("corrupted file\n");
-		free (ret);
-		return NULL;
-	}
-	libname = (char *)(bin->b->buf + image_infos[idx].pathFileOffset);
+	int pfo = image_infos[idx].pathFileOffset;
+	if (pfo < 0 || pfo > bin->size) {
+		eprintf ("corrupted file: pathFileOffset > bin->size (%d)\n", pfo);
+		free (ret);
+		return NULL;
+	}
+	libname = r_buf_read_string (bin->b, pfo, 64);
 	/* Locate lib hdr in cache */
 	data = bin->b->buf + liboff;
 	mh = (struct mach_header *)data;
@@ -224,16 +248,15 @@
 }
 
 struct r_bin_dyldcache_obj_t* r_bin_dyldcache_from_bytes_new(const ut8* buf, ut64 size) {
-	struct r_bin_dyldcache_obj_t *bin;
-	if (!(bin = malloc (sizeof (struct r_bin_dyldcache_obj_t)))) {
-		return NULL;
-	}
-	memset (bin, 0, sizeof (struct r_bin_dyldcache_obj_t));
+	struct r_bin_dyldcache_obj_t *bin = R_NEW0 (struct r_bin_dyldcache_obj_t);
+	if (!bin) {
+		return NULL;
+	}
 	if (!buf) {
 		return r_bin_dyldcache_free (bin);
 	}
-	bin->b = r_buf_new();
-	if (!r_buf_set_bytes (bin->b, buf, size)) {
+	bin->b = r_buf_new ();
+	if (!bin->b || !r_buf_set_bytes (bin->b, buf, size)) {
 		return r_bin_dyldcache_free (bin);
 	}
 	if (!r_bin_dyldcache_init (bin)) {
```
