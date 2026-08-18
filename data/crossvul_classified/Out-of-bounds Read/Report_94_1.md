# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 94_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `94_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 104-145 of the vulnerable file.

  X3F_EXT_TYPE_EXPOSURE_ADJUST=1,
  X3F_EXT_TYPE_CONTRAST_ADJUST=2,
  X3F_EXT_TYPE_SHADOW_ADJUST=3,
  X3F_EXT_TYPE_HIGHLIGHT_ADJUST=4,
  X3F_EXT_TYPE_SATURATION_ADJUST=5,
  X3F_EXT_TYPE_SHARPNESS_ADJUST=6,
  X3F_EXT_TYPE_RED_ADJUST=7,
  X3F_EXT_TYPE_GREEN_ADJUST=8,
  X3F_EXT_TYPE_BLUE_ADJUST=9,
  X3F_EXT_TYPE_FILL_LIGHT_ADJUST=10
} x3f_extended_types_t;

typedef struct x3f_property_s {
  /* Read from file */
  uint32_t name_offset;
  uint32_t value_offset;

  /* Computed */
  utf16_t *name;		/* 0x0000 terminated UTF 16 */
  utf16_t *value;               /* 0x0000 terminated UTF 16 */
  char *name_utf8;		/* converted to UTF 8 */
  char *value_utf8;          /* converted to UTF 8 */
} x3f_property_t;

typedef struct x3f_property_table_s {
  uint32_t size;
  x3f_property_t *element;
} x3f_property_table_t;

typedef struct x3f_property_list_s {
  /* 2.0 Fields */
  uint32_t num_properties;
  uint32_t character_format;
  uint32_t reserved;
  uint32_t total_length;

  x3f_property_table_t property_table;

  void *data;

  uint32_t data_size;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -121,8 +121,6 @@
   /* Computed */
   utf16_t *name;		/* 0x0000 terminated UTF 16 */
   utf16_t *value;               /* 0x0000 terminated UTF 16 */
-  char *name_utf8;		/* converted to UTF 8 */
-  char *value_utf8;          /* converted to UTF 8 */
 } x3f_property_t;
 
 typedef struct x3f_property_table_s {
@@ -516,7 +514,6 @@
 		int _cur = _file->_func(_buffer,1,_left);	\
 		if (_cur == 0) {							\
 			throw LIBRAW_EXCEPTION_IO_CORRUPT;		\
-			exit(1);								\
 		}											\
 		_left -= _cur;								\
 	}												\
@@ -912,11 +909,6 @@
 			if (PL)
 			{
 				int i;
-
-				for (i = 0; i < PL->property_table.size; i++) {
-					FREE(PL->property_table.element[i].name_utf8);
-					FREE(PL->property_table.element[i].value_utf8);
-				}
 			}
 			FREE(PL->property_table.element);
 			FREE(PL->data);
@@ -1624,14 +1616,14 @@
 
 	if (!PL->data_size)
 		PL->data_size = read_data_block(&PL->data, I, DE, 0);
+	uint32_t maxoffset = PL->data_size/sizeof(utf16_t)-2; // at least 2 chars, value + terminating 0x0000
 
 	for (i=0; i<PL->num_properties; i++) {
 		x3f_property_t *P = &PL->property_table.element[i];
-
+		if(P->name_offset > maxoffset || P->value_offset > maxoffset)
+			throw LIBRAW_EXCEPTION_IO_CORRUPT;
 		P->name = ((utf16_t *)PL->data + P->name_offset);
 		P->value = ((utf16_t *)PL->data + P->value_offset);
-		P->name_utf8 = 0;// utf16le_to_utf8(P->name);
-		P->value_utf8 = 0;//utf16le_to_utf8(P->value);
 	}
 }
 
```
