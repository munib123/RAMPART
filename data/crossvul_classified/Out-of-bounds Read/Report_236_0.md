# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 236_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `236_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3770-3810 of the vulnerable file.

		return NULL;
	}
	offset += 6;
	attr->type = R_BIN_JAVA_ATTR_TYPE_LINE_NUMBER_TABLE_ATTR;
	attr->info.line_number_table_attr.line_number_table_length = R_BIN_JAVA_USHORT (buffer, offset);
	offset += 2;
	attr->info.line_number_table_attr.line_number_table = r_list_newf (free);

	ut32 linenum_len = attr->info.line_number_table_attr.line_number_table_length;
	RList *linenum_list = attr->info.line_number_table_attr.line_number_table;
	if (linenum_len > sz) {
		free (attr);
		return NULL;
	}
	for (i = 0; i < linenum_len; i++) {
		curpos = buf_offset + offset;
		// printf ("%llx %llx \n", curpos, sz);
		// XXX if (curpos + 8 >= sz) break;
		lnattr = R_NEW0 (RBinJavaLineNumberAttribute);
		if (!lnattr) {
			break;
		}
		lnattr->start_pc = R_BIN_JAVA_USHORT (buffer, offset);
		offset += 2;
		lnattr->line_number = R_BIN_JAVA_USHORT (buffer, offset);
		offset += 2;
		lnattr->file_offset = curpos;
		lnattr->size = 4;
		r_list_append (linenum_list, lnattr);
	}
	attr->size = offset;
	return attr;
}

R_API ut64 r_bin_java_line_number_table_attr_calc_size(RBinJavaAttrInfo *attr) {
	ut64 size = 6;
	// RBinJavaLineNumberAttribute *lnattr;
	RListIter *iter;
	// RListIter *iter_tmp;
	if (!attr) {
		return 0LL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3789,6 +3789,9 @@
 		if (!lnattr) {
 			break;
 		}
+		if (offset + 8 >= sz) {
+			break;
+		}
 		lnattr->start_pc = R_BIN_JAVA_USHORT (buffer, offset);
 		offset += 2;
 		lnattr->line_number = R_BIN_JAVA_USHORT (buffer, offset);
```
