# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 180_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `180_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 45-85 of the vulnerable file.

	R_FREE (bb->label);
	R_FREE (bb->op_pos);
	R_FREE (bb->parent_reg_arena);
	if (bb->prev) {
		if (bb->prev->jumpbb == bb) {
			bb->prev->jumpbb = NULL;
		}
		if (bb->prev->failbb == bb) {
			bb->prev->failbb = NULL;
		}
		bb->prev = NULL;
	}
	if (bb->jumpbb) {
		bb->jumpbb->prev = NULL;
		bb->jumpbb = NULL;
	}
	if (bb->failbb) {
		bb->failbb->prev = NULL;
		bb->failbb = NULL;
	}
	R_FREE (bb);
}

R_API RList *r_anal_bb_list_new() {
	RList *list = r_list_newf ((RListFree)r_anal_bb_free);
	if (!list) {
		return NULL;
	}
	return list;
}

R_API int r_anal_bb(RAnal *anal, RAnalBlock *bb, ut64 addr, ut8 *buf, ut64 len, int head) {
	RAnalOp *op = NULL;
	int oplen, idx = 0;

	if (bb->addr == -1) {
		bb->addr = addr;
	}
	len -= 16; // XXX: hack to avoid segfault by x86im
	while (idx < len) {
		// TODO: too slow object construction
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,7 +62,11 @@
 		bb->failbb->prev = NULL;
 		bb->failbb = NULL;
 	}
-	R_FREE (bb);
+	if (bb->next) {
+		// avoid double free
+		bb->next->prev = NULL;
+	}
+	R_FREE (bb); // double free
 }
 
 R_API RList *r_anal_bb_list_new() {
```
