# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5500_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5500_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 2088-2130 of the vulnerable file.

}

static int em_iret(struct x86_emulate_ctxt *ctxt)
{
	switch(ctxt->mode) {
	case X86EMUL_MODE_REAL:
		return emulate_iret_real(ctxt);
	case X86EMUL_MODE_VM86:
	case X86EMUL_MODE_PROT16:
	case X86EMUL_MODE_PROT32:
	case X86EMUL_MODE_PROT64:
	default:
		/* iret from protected mode unimplemented yet */
		return X86EMUL_UNHANDLEABLE;
	}
}

static int em_jmp_far(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned short sel, old_sel;
	struct desc_struct old_desc, new_desc;
	const struct x86_emulate_ops *ops = ctxt->ops;
	u8 cpl = ctxt->ops->cpl(ctxt);

	/* Assignment of RIP may only fail in 64-bit mode */
	if (ctxt->mode == X86EMUL_MODE_PROT64)
		ops->get_segment(ctxt, &old_sel, &old_desc, NULL,
				 VCPU_SREG_CS);

	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);

	rc = __load_segment_descriptor(ctxt, sel, VCPU_SREG_CS, cpl,
				       X86_TRANSFER_CALL_JMP,
				       &new_desc);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = assign_eip_far(ctxt, ctxt->src.val, &new_desc);
	if (rc != X86EMUL_CONTINUE) {
		WARN_ON(ctxt->mode != X86EMUL_MODE_PROT64);
		/* assigning eip failed; restore the old cs */
		ops->set_segment(ctxt, old_sel, &old_desc, 0, VCPU_SREG_CS);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2105,15 +2105,9 @@
 static int em_jmp_far(struct x86_emulate_ctxt *ctxt)
 {
 	int rc;
-	unsigned short sel, old_sel;
-	struct desc_struct old_desc, new_desc;
-	const struct x86_emulate_ops *ops = ctxt->ops;
+	unsigned short sel;
+	struct desc_struct new_desc;
 	u8 cpl = ctxt->ops->cpl(ctxt);
-
-	/* Assignment of RIP may only fail in 64-bit mode */
-	if (ctxt->mode == X86EMUL_MODE_PROT64)
-		ops->get_segment(ctxt, &old_sel, &old_desc, NULL,
-				 VCPU_SREG_CS);
 
 	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);
 
@@ -2124,12 +2118,10 @@
 		return rc;
 
 	rc = assign_eip_far(ctxt, ctxt->src.val, &new_desc);
-	if (rc != X86EMUL_CONTINUE) {
-		WARN_ON(ctxt->mode != X86EMUL_MODE_PROT64);
-		/* assigning eip failed; restore the old cs */
-		ops->set_segment(ctxt, old_sel, &old_desc, 0, VCPU_SREG_CS);
-		return rc;
-	}
+	/* Error handling is not implemented. */
+	if (rc != X86EMUL_CONTINUE)
+		return X86EMUL_UNHANDLEABLE;
+
 	return rc;
 }
 
@@ -2189,14 +2181,8 @@
 {
 	int rc;
 	unsigned long eip, cs;
-	u16 old_cs;
 	int cpl = ctxt->ops->cpl(ctxt);
-	struct desc_struct old_desc, new_desc;
-	const struct x86_emulate_ops *ops = ctxt->ops;
-
-	if (ctxt->mode == X86EMUL_MODE_PROT64)
-		ops->get_segment(ctxt, &old_cs, &old_desc, NULL,
-				 VCPU_SREG_CS);
+	struct desc_struct new_desc;
 
 	rc = emulate_pop(ctxt, &eip, ctxt->op_bytes);
 	if (rc != X86EMUL_CONTINUE)
@@ -2213,10 +2199,10 @@
 	if (rc != X86EMUL_CONTINUE)
 		return rc;
 	rc = assign_eip_far(ctxt, eip, &new_desc);
-	if (rc != X86EMUL_CONTINUE) {
-		WARN_ON(ctxt->mode != X86EMUL_MODE_PROT64);
-		ops->set_segment(ctxt, old_cs, &old_desc, 0, VCPU_SREG_CS);
-	}
+	/* Error handling is not implemented. */
+	if (rc != X86EMUL_CONTINUE)
+		return X86EMUL_UNHANDLEABLE;
+
 	return rc;
 }
 
```
