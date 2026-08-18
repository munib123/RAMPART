# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2164_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2164_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 547-587 of the vulnerable file.

static int emulate_ud(struct x86_emulate_ctxt *ctxt)
{
	return emulate_exception(ctxt, UD_VECTOR, 0, false);
}

static int emulate_ts(struct x86_emulate_ctxt *ctxt, int err)
{
	return emulate_exception(ctxt, TS_VECTOR, err, true);
}

static int emulate_de(struct x86_emulate_ctxt *ctxt)
{
	return emulate_exception(ctxt, DE_VECTOR, 0, false);
}

static int emulate_nm(struct x86_emulate_ctxt *ctxt)
{
	return emulate_exception(ctxt, NM_VECTOR, 0, false);
}

static inline void assign_eip_near(struct x86_emulate_ctxt *ctxt, ulong dst)
{
	switch (ctxt->op_bytes) {
	case 2:
		ctxt->_eip = (u16)dst;
		break;
	case 4:
		ctxt->_eip = (u32)dst;
		break;
	case 8:
		ctxt->_eip = dst;
		break;
	default:
		WARN(1, "unsupported eip assignment size\n");
	}
}

static inline void jmp_rel(struct x86_emulate_ctxt *ctxt, int rel)
{
	assign_eip_near(ctxt, ctxt->_eip + rel);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -564,7 +564,8 @@
 	return emulate_exception(ctxt, NM_VECTOR, 0, false);
 }
 
-static inline void assign_eip_near(struct x86_emulate_ctxt *ctxt, ulong dst)
+static inline int assign_eip_far(struct x86_emulate_ctxt *ctxt, ulong dst,
+			       int cs_l)
 {
 	switch (ctxt->op_bytes) {
 	case 2:
@@ -574,16 +575,25 @@
 		ctxt->_eip = (u32)dst;
 		break;
 	case 8:
+		if ((cs_l && is_noncanonical_address(dst)) ||
+		    (!cs_l && (dst & ~(u32)-1)))
+			return emulate_gp(ctxt, 0);
 		ctxt->_eip = dst;
 		break;
 	default:
 		WARN(1, "unsupported eip assignment size\n");
 	}
-}
-
-static inline void jmp_rel(struct x86_emulate_ctxt *ctxt, int rel)
-{
-	assign_eip_near(ctxt, ctxt->_eip + rel);
+	return X86EMUL_CONTINUE;
+}
+
+static inline int assign_eip_near(struct x86_emulate_ctxt *ctxt, ulong dst)
+{
+	return assign_eip_far(ctxt, dst, ctxt->mode == X86EMUL_MODE_PROT64);
+}
+
+static inline int jmp_rel(struct x86_emulate_ctxt *ctxt, int rel)
+{
+	return assign_eip_near(ctxt, ctxt->_eip + rel);
 }
 
 static u16 get_segment_selector(struct x86_emulate_ctxt *ctxt, unsigned seg)
@@ -1998,13 +2008,15 @@
 	case 2: /* call near abs */ {
 		long int old_eip;
 		old_eip = ctxt->_eip;
-		ctxt->_eip = ctxt->src.val;
+		rc = assign_eip_near(ctxt, ctxt->src.val);
+		if (rc != X86EMUL_CONTINUE)
+			break;
 		ctxt->src.val = old_eip;
 		rc = em_push(ctxt);
 		break;
 	}
 	case 4: /* jmp abs */
-		ctxt->_eip = ctxt->src.val;
+		rc = assign_eip_near(ctxt, ctxt->src.val);
 		break;
 	case 5: /* jmp far */
 		rc = em_jmp_far(ctxt);
@@ -2039,10 +2051,14 @@
 
 static int em_ret(struct x86_emulate_ctxt *ctxt)
 {
-	ctxt->dst.type = OP_REG;
-	ctxt->dst.addr.reg = &ctxt->_eip;
-	ctxt->dst.bytes = ctxt->op_bytes;
-	return em_pop(ctxt);
+	int rc;
+	unsigned long eip;
+
+	rc = emulate_pop(ctxt, &eip, ctxt->op_bytes);
+	if (rc != X86EMUL_CONTINUE)
+		return rc;
+
+	return assign_eip_near(ctxt, eip);
 }
 
 static int em_ret_far(struct x86_emulate_ctxt *ctxt)
@@ -2323,7 +2339,7 @@
 {
 	const struct x86_emulate_ops *ops = ctxt->ops;
 	struct desc_struct cs, ss;
-	u64 msr_data;
+	u64 msr_data, rcx, rdx;
 	int usermode;
 	u16 cs_sel = 0, ss_sel = 0;
 
@@ -2338,6 +2354,9 @@
 		usermode = X86EMUL_MODE_PROT64;
 	else
 		usermode = X86EMUL_MODE_PROT32;
+
+	rcx = reg_read(ctxt, VCPU_REGS_RCX);
+	rdx = reg_read(ctxt, VCPU_REGS_RDX);
 
 	cs.dpl = 3;
 	ss.dpl = 3;
@@ -2356,6 +2375,9 @@
 		ss_sel = cs_sel + 8;
 		cs.d = 0;
 		cs.l = 1;
+		if (is_noncanonical_address(rcx) ||
+		    is_noncanonical_address(rdx))
+			return emulate_gp(ctxt, 0);
 		break;
 	}
 	cs_sel |= SELECTOR_RPL_MASK;
@@ -2364,8 +2386,8 @@
 	ops->set_segment(ctxt, cs_sel, &cs, 0, VCPU_SREG_CS);
 	ops->set_segment(ctxt, ss_sel, &ss, 0, VCPU_SREG_SS);
 
-	ctxt->_eip = reg_read(ctxt, VCPU_REGS_RDX);
-	*reg_write(ctxt, VCPU_REGS_RSP) = reg_read(ctxt, VCPU_REGS_RCX);
+	ctxt->_eip = rdx;
+	*reg_write(ctxt, VCPU_REGS_RSP) = rcx;
 
 	return X86EMUL_CONTINUE;
 }
@@ -2905,10 +2927,13 @@
 
 static int em_call(struct x86_emulate_ctxt *ctxt)
 {
+	int rc;
 	long rel = ctxt->src.val;
 
 	ctxt->src.val = (unsigned long)ctxt->_eip;
-	jmp_rel(ctxt, rel);
+	rc = jmp_rel(ctxt, rel);
+	if (rc != X86EMUL_CONTINUE)
+		return rc;
 	return em_push(ctxt);
 }
 
@@ -2940,11 +2965,12 @@
 static int em_ret_near_imm(struct x86_emulate_ctxt *ctxt)
 {
 	int rc;
-
-	ctxt->dst.type = OP_REG;
-	ctxt->dst.addr.reg = &ctxt->_eip;
-	ctxt->dst.bytes = ctxt->op_bytes;
-	rc = emulate_pop(ctxt, &ctxt->dst.val, ctxt->op_bytes);
+	unsigned long eip;
+
+	rc = emulate_pop(ctxt, &eip, ctxt->op_bytes);
+	if (rc != X86EMUL_CONTINUE)
+		return rc;
+	rc = assign_eip_near(ctxt, eip);
 	if (rc != X86EMUL_CONTINUE)
 		return rc;
 	rsp_increment(ctxt, ctxt->src.val);
@@ -3271,20 +3297,24 @@
 
 static int em_loop(struct x86_emulate_ctxt *ctxt)
 {
+	int rc = X86EMUL_CONTINUE;
+
 	register_address_increment(ctxt, reg_rmw(ctxt, VCPU_REGS_RCX), -1);
 	if ((address_mask(ctxt, reg_read(ctxt, VCPU_REGS_RCX)) != 0) &&
 	    (ctxt->b == 0xe2 || test_cc(ctxt->b ^ 0x5, ctxt->eflags)))
-		jmp_rel(ctxt, ctxt->src.val);
-
-	return X86EMUL_CONTINUE;
+		rc = jmp_rel(ctxt, ctxt->src.val);
+
+	return rc;
 }
 
 static int em_jcxz(struct x86_emulate_ctxt *ctxt)
 {
+	int rc = X86EMUL_CONTINUE;
+
 	if (address_mask(ctxt, reg_read(ctxt, VCPU_REGS_RCX)) == 0)
-		jmp_rel(ctxt, ctxt->src.val);
-
-	return X86EMUL_CONTINUE;
+		rc = jmp_rel(ctxt, ctxt->src.val);
+
+	return rc;
 }
 
 static int em_in(struct x86_emulate_ctxt *ctxt)
@@ -4743,7 +4773,7 @@
 		break;
 	case 0x70 ... 0x7f: /* jcc (short) */
 		if (test_cc(ctxt->b, ctxt->eflags))
-			jmp_rel(ctxt, ctxt->src.val);
+			rc = jmp_rel(ctxt, ctxt->src.val);
 		break;
 	case 0x8d: /* lea r16/r32, m */
 		ctxt->dst.val = ctxt->src.addr.mem.ea;
@@ -4773,7 +4803,7 @@
 		break;
 	case 0xe9: /* jmp rel */
 	case 0xeb: /* jmp rel short */
-		jmp_rel(ctxt, ctxt->src.val);
+		rc = jmp_rel(ctxt, ctxt->src.val);
 		ctxt->dst.type = OP_NONE; /* Disable writeback. */
 		break;
 	case 0xf4:              /* hlt */
@@ -4898,7 +4928,7 @@
 		break;
 	case 0x80 ... 0x8f: /* jnz rel, etc*/
 		if (test_cc(ctxt->b, ctxt->eflags))
-			jmp_rel(ctxt, ctxt->src.val);
+			rc = jmp_rel(ctxt, ctxt->src.val);
 		break;
 	case 0x90 ... 0x9f:     /* setcc r/m8 */
 		ctxt->dst.val = test_cc(ctxt->b, ctxt->eflags);
```
