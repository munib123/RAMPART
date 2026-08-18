# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2935_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2935_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 605-645 of the vulnerable file.

} RBinDwarfAddressRangeTable;

typedef struct {
	ut64	attr_name;
	ut64	attr_form;
} RBinDwarfAttrSpec;

typedef struct {
	ut64	length;
	ut8	*data;
} RBinDwarfBlock;

typedef union {
	ut64	address;
	RBinDwarfBlock block;
	ut64	constant;
	ut8	flag;
	ut64	data;
	st64	sdata;
	ut64	reference;
	struct str_structt {
		char	*string;
		ut64	offset;
	} str_struct;
} RBinDwarfAttrEnc;

typedef struct {
	ut64 name;
	ut64 form;
	RBinDwarfAttrEnc encoding;
} RBinDwarfAttrValue;

typedef struct {
	ut32	length;
	ut16	version;
	ut32	abbrev_offset;
	ut8	pointer_size;
} RBinDwarfCompUnitHdr;

typedef struct {
	ut64	tag;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -622,7 +622,7 @@
 	ut64	data;
 	st64	sdata;
 	ut64	reference;
-	struct str_structt {
+	struct {
 		char	*string;
 		ut64	offset;
 	} str_struct;
```
