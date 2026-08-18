# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3045_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3045_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 799-839 of the vulnerable file.

	return rc;
}

static inline int jmp_rel(struct x86_emulate_ctxt *ctxt, int rel)
{
	return assign_eip_near(ctxt, ctxt->_eip + rel);
}

static int segmented_read_std(struct x86_emulate_ctxt *ctxt,
			      struct segmented_address addr,
			      void *data,
			      unsigned size)
{
	int rc;
	ulong linear;

	rc = linearize(ctxt, addr, size, false, &linear);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	return ctxt->ops->read_std(ctxt, linear, data, size, &ctxt->exception);
}

/*
 * Prefetch the remaining bytes of the instruction without crossing page
 * boundary if they are not in fetch_cache yet.
 */
static int __do_insn_fetch_bytes(struct x86_emulate_ctxt *ctxt, int op_size)
{
	int rc;
	unsigned size, max_size;
	unsigned long linear;
	int cur_size = ctxt->fetch.end - ctxt->fetch.data;
	struct segmented_address addr = { .seg = VCPU_SREG_CS,
					   .ea = ctxt->eip + cur_size };

	/*
	 * We do not know exactly how many bytes will be needed, and
	 * __linearize is expensive, so fetch as much as possible.  We
	 * just have to avoid going beyond the 15 byte limit, the end
	 * of the segment, or the end of the page.
	 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -818,6 +818,20 @@
 	return ctxt->ops->read_std(ctxt, linear, data, size, &ctxt->exception);
 }
 
+static int segmented_write_std(struct x86_emulate_ctxt *ctxt,
+			       struct segmented_address addr,
+			       void *data,
+			       unsigned int size)
+{
+	int rc;
+	ulong linear;
+
+	rc = linearize(ctxt, addr, size, true, &linear);
+	if (rc != X86EMUL_CONTINUE)
+		return rc;
+	return ctxt->ops->write_std(ctxt, linear, data, size, &ctxt->exception);
+}
+
 /*
  * Prefetch the remaining bytes of the instruction without crossing page
  * boundary if they are not in fetch_cache yet.
@@ -3685,8 +3699,8 @@
 	}
 	/* Disable writeback. */
 	ctxt->dst.type = OP_NONE;
-	return segmented_write(ctxt, ctxt->dst.addr.mem,
-			       &desc_ptr, 2 + ctxt->op_bytes);
+	return segmented_write_std(ctxt, ctxt->dst.addr.mem,
+				   &desc_ptr, 2 + ctxt->op_bytes);
 }
 
 static int em_sgdt(struct x86_emulate_ctxt *ctxt)
@@ -3932,7 +3946,7 @@
 	else
 		size = offsetof(struct fxregs_state, xmm_space[0]);
 
-	return segmented_write(ctxt, ctxt->memop.addr.mem, &fx_state, size);
+	return segmented_write_std(ctxt, ctxt->memop.addr.mem, &fx_state, size);
 }
 
 static int fxrstor_fixup(struct x86_emulate_ctxt *ctxt,
@@ -3974,7 +3988,7 @@
 	if (rc != X86EMUL_CONTINUE)
 		return rc;
 
-	rc = segmented_read(ctxt, ctxt->memop.addr.mem, &fx_state, 512);
+	rc = segmented_read_std(ctxt, ctxt->memop.addr.mem, &fx_state, 512);
 	if (rc != X86EMUL_CONTINUE)
 		return rc;
 
```
