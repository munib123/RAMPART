# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 234_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `234_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1344-1384 of the vulnerable file.


		if (da->capacity < abbr_code) {
			return NULL;
		}

		for (i = 0; i < da->decls[abbr_code - 1].length; i++) {
			if (cu->dies[cu->length].length == cu->dies[cu->length].capacity) {
				r_bin_dwarf_expand_die (&cu->dies[cu->length]);
			}
			if (i >= cu->dies[cu->length].capacity || i >= da->decls[abbr_code - 1].capacity) {
				eprintf ("Warning: malformed dwarf attribute capacity doesn't match length\n");
				break;
			}
			memset (&cu->dies[cu->length].attr_values[i], 0, sizeof (cu->dies[cu->length].attr_values[i]));
			buf = r_bin_dwarf_parse_attr_value (buf, buf_end - buf,
					&da->decls[abbr_code - 1].specs[i],
					&cu->dies[cu->length].attr_values[i],
					&cu->hdr, debug_str, debug_str_len);
			if (cu->dies[cu->length].attr_values[i].name == DW_AT_comp_dir) {
				const char *name = cu->dies[cu->length].attr_values[i].encoding.str_struct.string;
				sdb_set (s, "DW_AT_comp_dir", name, 0);
			}
			cu->dies[cu->length].length++;
		}
		cu->length++;
	}
	return buf;
}

R_API int r_bin_dwarf_parse_info_raw(Sdb *s, RBinDwarfDebugAbbrev *da,
		const ut8 *obuf, size_t len,
		const ut8 *debug_str, size_t debug_str_len, int mode) {
	const ut8 *buf = obuf, *buf_end = obuf + len;
	size_t k, offset = 0;
	int curr_unit = 0;
	RBinDwarfDebugInfo di = {0};
	RBinDwarfDebugInfo *inf = &di;
	bool ret = true;

	if (!da || !s || !obuf) {
		return false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1361,7 +1361,11 @@
 					&cu->hdr, debug_str, debug_str_len);
 			if (cu->dies[cu->length].attr_values[i].name == DW_AT_comp_dir) {
 				const char *name = cu->dies[cu->length].attr_values[i].encoding.str_struct.string;
-				sdb_set (s, "DW_AT_comp_dir", name, 0);
+				if (name > 1024) { // solve some null derefs
+					sdb_set (s, "DW_AT_comp_dir", name, 0);
+				} else {
+					eprintf ("Invalid string pointer at %p\n", name);
+				}
 			}
 			cu->dies[cu->length].length++;
 		}
```
