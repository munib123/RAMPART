# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5675_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5675_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-24 of the vulnerable file.

#ifndef ISCSI_PARAMETERS_H
#define ISCSI_PARAMETERS_H

struct iscsi_extra_response {
	char key[64];
	char value[32];
	struct list_head er_list;
} ____cacheline_aligned;

struct iscsi_param {
	char *name;
	char *value;
	u8 set_param;
	u8 phase;
	u8 scope;
	u8 sender;
	u8 type;
	u8 use;
	u16 type_range;
	u32 state;
	struct list_head p_list;
} ____cacheline_aligned;

extern int iscsi_login_rx_data(struct iscsi_conn *, char *, int);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,8 +1,10 @@
 #ifndef ISCSI_PARAMETERS_H
 #define ISCSI_PARAMETERS_H
 
+#include <scsi/iscsi_proto.h>
+
 struct iscsi_extra_response {
-	char key[64];
+	char key[KEY_MAXLEN];
 	char value[32];
 	struct list_head er_list;
 } ____cacheline_aligned;
```
