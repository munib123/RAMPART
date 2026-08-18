# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 916_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `916_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 540-580 of the vulnerable file.

	}

	*offs1 = regoff1[X86_MODRM_RM(insn->modrm.value)];
	*offs2 = regoff2[X86_MODRM_RM(insn->modrm.value)];

	/*
	 * If ModRM.mod is 0 and ModRM.rm is 110b, then we use displacement-
	 * only addressing. This means that no registers are involved in
	 * computing the effective address. Thus, ensure that the first
	 * register offset is invalild. The second register offset is already
	 * invalid under the aforementioned conditions.
	 */
	if ((X86_MODRM_MOD(insn->modrm.value) == 0) &&
	    (X86_MODRM_RM(insn->modrm.value) == 6))
		*offs1 = -EDOM;

	return 0;
}

/**
 * get_desc() - Obtain pointer to a segment descriptor
 * @sel:	Segment selector
 *
 * Given a segment selector, obtain a pointer to the segment descriptor.
 * Both global and local descriptor tables are supported.
 *
 * Returns:
 *
 * Pointer to segment descriptor on success.
 *
 * NULL on error.
 */
static struct desc_struct *get_desc(unsigned short sel)
{
	struct desc_ptr gdt_desc = {0, 0};
	unsigned long desc_base;

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	if ((sel & SEGMENT_TI_MASK) == SEGMENT_LDT) {
		struct desc_struct *desc = NULL;
		struct ldt_struct *ldt;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -557,7 +557,8 @@
 }
 
 /**
- * get_desc() - Obtain pointer to a segment descriptor
+ * get_desc() - Obtain contents of a segment descriptor
+ * @out:	Segment descriptor contents on success
  * @sel:	Segment selector
  *
  * Given a segment selector, obtain a pointer to the segment descriptor.
@@ -565,18 +566,18 @@
  *
  * Returns:
  *
- * Pointer to segment descriptor on success.
+ * True on success, false on failure.
  *
  * NULL on error.
  */
-static struct desc_struct *get_desc(unsigned short sel)
+static bool get_desc(struct desc_struct *out, unsigned short sel)
 {
 	struct desc_ptr gdt_desc = {0, 0};
 	unsigned long desc_base;
 
 #ifdef CONFIG_MODIFY_LDT_SYSCALL
 	if ((sel & SEGMENT_TI_MASK) == SEGMENT_LDT) {
-		struct desc_struct *desc = NULL;
+		bool success = false;
 		struct ldt_struct *ldt;
 
 		/* Bits [15:3] contain the index of the desired entry. */
@@ -584,12 +585,14 @@
 
 		mutex_lock(&current->active_mm->context.lock);
 		ldt = current->active_mm->context.ldt;
-		if (ldt && sel < ldt->nr_entries)
-			desc = &ldt->entries[sel];
+		if (ldt && sel < ldt->nr_entries) {
+			*out = ldt->entries[sel];
+			success = true;
+		}
 
 		mutex_unlock(&current->active_mm->context.lock);
 
-		return desc;
+		return success;
 	}
 #endif
 	native_store_gdt(&gdt_desc);
@@ -604,9 +607,10 @@
 	desc_base = sel & ~(SEGMENT_RPL_MASK | SEGMENT_TI_MASK);
 
 	if (desc_base > gdt_desc.size)
-		return NULL;
-
-	return (struct desc_struct *)(gdt_desc.address + desc_base);
+		return false;
+
+	*out = *(struct desc_struct *)(gdt_desc.address + desc_base);
+	return true;
 }
 
 /**
@@ -628,7 +632,7 @@
  */
 unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
 {
-	struct desc_struct *desc;
+	struct desc_struct desc;
 	short sel;
 
 	sel = get_segment_selector(regs, seg_reg_idx);
@@ -666,11 +670,10 @@
 	if (!sel)
 		return -1L;
 
-	desc = get_desc(sel);
-	if (!desc)
+	if (!get_desc(&desc, sel))
 		return -1L;
 
-	return get_desc_base(desc);
+	return get_desc_base(&desc);
 }
 
 /**
@@ -692,7 +695,7 @@
  */
 static unsigned long get_seg_limit(struct pt_regs *regs, int seg_reg_idx)
 {
-	struct desc_struct *desc;
+	struct desc_struct desc;
 	unsigned long limit;
 	short sel;
 
@@ -706,8 +709,7 @@
 	if (!sel)
 		return 0;
 
-	desc = get_desc(sel);
-	if (!desc)
+	if (!get_desc(&desc, sel))
 		return 0;
 
 	/*
@@ -716,8 +718,8 @@
 	 * not tested when checking the segment limits. In practice,
 	 * this means that the segment ends in (limit << 12) + 0xfff.
 	 */
-	limit = get_desc_limit(desc);
-	if (desc->g)
+	limit = get_desc_limit(&desc);
+	if (desc.g)
 		limit = (limit << 12) + 0xfff;
 
 	return limit;
@@ -741,7 +743,7 @@
  */
 int insn_get_code_seg_params(struct pt_regs *regs)
 {
-	struct desc_struct *desc;
+	struct desc_struct desc;
 	short sel;
 
 	if (v8086_mode(regs))
@@ -752,8 +754,7 @@
 	if (sel < 0)
 		return sel;
 
-	desc = get_desc(sel);
-	if (!desc)
+	if (!get_desc(&desc, sel))
 		return -EINVAL;
 
 	/*
@@ -761,10 +762,10 @@
 	 * determines whether a segment contains data or code. If this is a data
 	 * segment, return error.
 	 */
-	if (!(desc->type & BIT(3)))
-		return -EINVAL;
-
-	switch ((desc->l << 1) | desc->d) {
+	if (!(desc.type & BIT(3)))
+		return -EINVAL;
+
+	switch ((desc.l << 1) | desc.d) {
 	case 0: /*
 		 * Legacy mode. CS.L=0, CS.D=0. Address and operand size are
 		 * both 16-bit.
```
