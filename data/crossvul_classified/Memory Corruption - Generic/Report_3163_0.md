# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3163_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3163_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-35 of the vulnerable file.

/* radare - LGPL - Copyright 2016 - Oscar Salvador */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include "bflt/bflt.h"

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loaddr, Sdb *sdb) {
	if (!buf || !sz || sz == UT64_MAX) {
		return NULL;
	}
	RBuffer *tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	struct r_bin_bflt_obj *res = r_bin_bflt_new_buf (tbuf);
	r_buf_free (tbuf);
	return res ? res : NULL;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = r_buf_buffer (arch->buf);
	ut64 sz = r_buf_size (arch->buf);
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? true : false;
}

static RList *entries(RBinFile *arch) {
	struct r_bin_bflt_obj *obj = (struct r_bin_bflt_obj*)arch->o->bin_obj;
	RList *ret;
	RBinAddr *ptr;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,6 +12,9 @@
 		return NULL;
 	}
 	RBuffer *tbuf = r_buf_new ();
+	if (!tbuf) {
+		return NULL;
+	}
 	r_buf_set_bytes (tbuf, buf, sz);
 	struct r_bin_bflt_obj *res = r_bin_bflt_new_buf (tbuf);
 	r_buf_free (tbuf);
@@ -47,7 +50,8 @@
 	r_buf_write_at (buf, addr_to_patch, (void *)val, sizeof (val));
 }
 
-static int search_old_relocation(struct reloc_struct_t *reloc_table, ut32 addr_to_patch, int n_reloc) {
+static int search_old_relocation (struct reloc_struct_t *reloc_table,
+				  ut32 addr_to_patch, int n_reloc) {
 	int i;
 	for (i = 0; i < n_reloc; i++) {
 		if (addr_to_patch == reloc_table[i].data_offset) {
@@ -163,7 +167,8 @@
 			if (amount < n_got || amount > UT32_MAX) {
 				goto out_error;
 			}
-			struct reloc_struct_t *got_table = calloc (1, n_got * sizeof (ut32));
+			struct reloc_struct_t *got_table = calloc (
+				1, n_got * sizeof (struct reloc_struct_t));
 			if (got_table) {
 				ut32 offset = 0;
 				for (i = 0; i < n_got ; offset += 4, i++) {
```
