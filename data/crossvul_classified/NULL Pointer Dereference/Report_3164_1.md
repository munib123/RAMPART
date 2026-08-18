# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3164_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3164_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1305-1345 of the vulnerable file.

		r_list_free (cls->methods);
		free (cls);
		return;
	}
	r_list_append (bin->classes_list, cls);
	if (dexdump) {
		rbin->cb_printf ("  Class descriptor  : '%s;'\n", class_name);
		rbin->cb_printf (
			"  Access flags      : 0x%04x (%s)\n", c->access_flags,
			createAccessFlagStr (c->access_flags, kAccessForClass));
		rbin->cb_printf ("  Superclass        : '%s'\n",
				 dex_class_super_name (bin, c));
		rbin->cb_printf ("  Interfaces        -\n");
	}

	if (c->interfaces_offset > 0 &&
	    bin->header.data_offset < c->interfaces_offset &&
	    c->interfaces_offset <
		    bin->header.data_offset + bin->header.data_size) {
		p = r_buf_get_at (binfile->buf, c->interfaces_offset, NULL);
		int types_list_size = r_read_le32(p);
		if (types_list_size < 0 || types_list_size >= bin->header.types_size ) {
			return;
		}
		for (z = 0; z < types_list_size; z++) {
			int t = r_read_le16 (p + 4 + z * 2);
			if (t > 0 && t < bin->header.types_size ) {
				int tid = bin->types[t].descriptor_id;
				if (dexdump) {
					rbin->cb_printf (
						"    #%d              : '%s'\n",
						z, getstr (bin, tid));
				}
			}
		}
	}

	// TODO: this is quite ugly
	if (!c || !c->class_data_offset) {
		if (dexdump) {
			rbin->cb_printf (
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1322,7 +1322,7 @@
 	    c->interfaces_offset <
 		    bin->header.data_offset + bin->header.data_size) {
 		p = r_buf_get_at (binfile->buf, c->interfaces_offset, NULL);
-		int types_list_size = r_read_le32(p);
+		int types_list_size = r_read_le32 (p);
 		if (types_list_size < 0 || types_list_size >= bin->header.types_size ) {
 			return;
 		}
```
