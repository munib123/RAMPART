# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2935_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2935_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/* radare - LGPL - Copyright 2012-2016 - pancake, Fedor Sakharov */

#define D0 if(1)
#define D1 if(1)

#include <errno.h>

#define DWARF_DUMP 0

#if DWARF_DUMP
#define DBGFD stdout
#else
#define DBGFD NULL
#endif

#include <r_bin.h>
#include <r_bin_dwarf.h>
#include <r_core.h>

#define STANDARD_OPERAND_COUNT_DWARF2 9
#define STANDARD_OPERAND_COUNT_DWARF3 12
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/* radare - LGPL - Copyright 2012-2016 - pancake, Fedor Sakharov */
+/* radare - LGPL - Copyright 2012-2017 - pancake, Fedor Sakharov */
 
 #define D0 if(1)
 #define D1 if(1)
@@ -1144,8 +1144,9 @@
 			values = dies[j].attr_values;
 
 			for (k = 0; k < dies[j].length; k++) {
-				if (!values[k].name)
+				if (!values[k].name) {
 					continue;
+				}
 
 				if (values[k].name < DW_AT_vtable_elem_location &&
 						dwarf_attr_encodings[values[k].name]) {
@@ -1168,7 +1169,7 @@
 	const ut8 *buf_end = obuf + obuf_len;
 	size_t j;
 
-	if (!spec || !value || !hdr || !obuf || obuf_len < 0) {
+	if (!spec || !value || !hdr || !obuf || obuf_len < 1) {
 		return NULL;
 	}
 
@@ -1194,7 +1195,7 @@
 			value->encoding.address = READ (buf, ut64);
 			break;
 		default:
-			eprintf("DWARF: Unexpected pointer size: %u\n", (unsigned)hdr->pointer_size);
+			eprintf ("DWARF: Unexpected pointer size: %u\n", (unsigned)hdr->pointer_size);
 			return NULL;
 		}
 		break;
@@ -1219,6 +1220,8 @@
 			value->encoding.block.data = data;
 		}
 		break;
+#if 0
+// This causes segfaults to happen
 	case DW_FORM_data2:
 		value->encoding.data = READ (buf, ut16);
 		break;
@@ -1228,6 +1231,7 @@
 	case DW_FORM_data8:
 		value->encoding.data = READ (buf, ut64);
 		break;
+#endif
 	case DW_FORM_string:
 		value->encoding.str_struct.string = *buf? strdup ((const char*)buf) : NULL;
 		buf += (strlen ((const char*)buf) + 1);
@@ -1237,16 +1241,20 @@
 		if (!buf) {
 			return NULL;
 		}
-		value->encoding.block.data = calloc (sizeof(ut8), value->encoding.block.length);
-		for (j = 0; j < value->encoding.block.length; j++) {
-			value->encoding.block.data[j] = READ (buf, ut8);
+		value->encoding.block.data = calloc (sizeof (ut8), value->encoding.block.length);
+		if (value->encoding.block.data) {
+			for (j = 0; j < value->encoding.block.length; j++) {
+				value->encoding.block.data[j] = READ (buf, ut8);
+			}
 		}
 		break;
 	case DW_FORM_block1:
 		value->encoding.block.length = READ (buf, ut8);
 		value->encoding.block.data = calloc (sizeof (ut8), value->encoding.block.length + 1);
-		for (j = 0; j < value->encoding.block.length; j++) {
-			value->encoding.block.data[j] = READ (buf, ut8);
+		if (value->encoding.block.data) {
+			for (j = 0; j < value->encoding.block.length; j++) {
+				value->encoding.block.data[j] = READ (buf, ut8);
+			}
 		}
 		break;
 	case DW_FORM_flag:
@@ -1344,8 +1352,7 @@
 				eprintf ("Warning: malformed dwarf attribute capacity doesn't match length\n");
 				break;
 			}
-			memset (&cu->dies[cu->length].attr_values[i], 0, sizeof
-					(cu->dies[cu->length].attr_values[i]));
+			memset (&cu->dies[cu->length].attr_values[i], 0, sizeof (cu->dies[cu->length].attr_values[i]));
 			buf = r_bin_dwarf_parse_attr_value (buf, buf_end - buf,
 					&da->decls[abbr_code - 1].specs[i],
 					&cu->dies[cu->length].attr_values[i],
```
