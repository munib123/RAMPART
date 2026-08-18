# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2371_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2371_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 266-308 of the vulnerable file.

 *
 * This could still be optimized:
 * - fold all the options into a flag word and test it with a single test.
 * - could test fs/gs bitsliced
 *
 * Kprobes not supported here. Set the probe on schedule instead.
 * Function graph tracer not supported too.
 */
__visible __notrace_funcgraph struct task_struct *
__switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread;
	struct thread_struct *next = &next_p->thread;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);
	unsigned fsindex, gsindex;
	fpu_switch_t fpu;

	fpu = switch_fpu_prepare(prev_p, next_p, cpu);

	/*
	 * Reload esp0, LDT and the page table pointer:
	 */
	load_sp0(tss, next);

	/*
	 * Switch DS and ES.
	 * This won't pick up thread selector changes, but I guess that is ok.
	 */
	savesegment(es, prev->es);
	if (unlikely(next->es | prev->es))
		loadsegment(es, next->es);

	savesegment(ds, prev->ds);
	if (unlikely(next->ds | prev->ds))
		loadsegment(ds, next->ds);


	/* We must save %fs and %gs before load_TLS() because
	 * %fs and %gs may be cleared by load_TLS().
	 *
	 * (e.g. xen_load_tls())
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -283,14 +283,45 @@
 
 	fpu = switch_fpu_prepare(prev_p, next_p, cpu);
 
+	/* Reload esp0 and ss1. */
+	load_sp0(tss, next);
+
+	/* We must save %fs and %gs before load_TLS() because
+	 * %fs and %gs may be cleared by load_TLS().
+	 *
+	 * (e.g. xen_load_tls())
+	 */
+	savesegment(fs, fsindex);
+	savesegment(gs, gsindex);
+
 	/*
-	 * Reload esp0, LDT and the page table pointer:
-	 */
-	load_sp0(tss, next);
+	 * Load TLS before restoring any segments so that segment loads
+	 * reference the correct GDT entries.
+	 */
+	load_TLS(next, cpu);
 
 	/*
-	 * Switch DS and ES.
-	 * This won't pick up thread selector changes, but I guess that is ok.
+	 * Leave lazy mode, flushing any hypercalls made here.  This
+	 * must be done after loading TLS entries in the GDT but before
+	 * loading segments that might reference them, and and it must
+	 * be done before math_state_restore, so the TS bit is up to
+	 * date.
+	 */
+	arch_end_context_switch(next_p);
+
+	/* Switch DS and ES.
+	 *
+	 * Reading them only returns the selectors, but writing them (if
+	 * nonzero) loads the full descriptor from the GDT or LDT.  The
+	 * LDT for next is loaded in switch_mm, and the GDT is loaded
+	 * above.
+	 *
+	 * We therefore need to write new values to the segment
+	 * registers on every context switch unless both the new and old
+	 * values are zero.
+	 *
+	 * Note that we don't need to do anything for CS and SS, as
+	 * those are saved and restored as part of pt_regs.
 	 */
 	savesegment(es, prev->es);
 	if (unlikely(next->es | prev->es))
@@ -300,50 +331,64 @@
 	if (unlikely(next->ds | prev->ds))
 		loadsegment(ds, next->ds);
 
-
-	/* We must save %fs and %gs before load_TLS() because
-	 * %fs and %gs may be cleared by load_TLS().
-	 *
-	 * (e.g. xen_load_tls())
-	 */
-	savesegment(fs, fsindex);
-	savesegment(gs, gsindex);
-
-	load_TLS(next, cpu);
-
-	/*
-	 * Leave lazy mode, flushing any hypercalls made here.
-	 * This must be done before restoring TLS segments so
-	 * the GDT and LDT are properly updated, and must be
-	 * done before math_state_restore, so the TS bit is up
-	 * to date.
-	 */
-	arch_end_context_switch(next_p);
-
 	/*
 	 * Switch FS and GS.
 	 *
-	 * Segment register != 0 always requires a reload.  Also
-	 * reload when it has changed.  When prev process used 64bit
-	 * base always reload to avoid an information leak.
+	 * These are even more complicated than FS and GS: they have
+	 * 64-bit bases are that controlled by arch_prctl.  Those bases
+	 * only differ from the values in the GDT or LDT if the selector
+	 * is 0.
+	 *
+	 * Loading the segment register resets the hidden base part of
+	 * the register to 0 or the value from the GDT / LDT.  If the
+	 * next base address zero, writing 0 to the segment register is
+	 * much faster than using wrmsr to explicitly zero the base.
+	 *
+	 * The thread_struct.fs and thread_struct.gs values are 0
+	 * if the fs and gs bases respectively are not overridden
+	 * from the values implied by fsindex and gsindex.  They
+	 * are nonzero, and store the nonzero base addresses, if
+	 * the bases are overridden.
+	 *
+	 * (fs != 0 && fsindex != 0) || (gs != 0 && gsindex != 0) should
+	 * be impossible.
+	 *
+	 * Therefore we need to reload the segment registers if either
+	 * the old or new selector is nonzero, and we need to override
+	 * the base address if next thread expects it to be overridden.
+	 *
+	 * This code is unnecessarily slow in the case where the old and
+	 * new indexes are zero and the new base is nonzero -- it will
+	 * unnecessarily write 0 to the selector before writing the new
+	 * base address.
+	 *
+	 * Note: This all depends on arch_prctl being the only way that
+	 * user code can override the segment base.  Once wrfsbase and
+	 * wrgsbase are enabled, most of this code will need to change.
 	 */
 	if (unlikely(fsindex | next->fsindex | prev->fs)) {
 		loadsegment(fs, next->fsindex);
+
 		/*
-		 * Check if the user used a selector != 0; if yes
-		 *  clear 64bit base, since overloaded base is always
-		 *  mapped to the Null selector
+		 * If user code wrote a nonzero value to FS, then it also
+		 * cleared the overridden base address.
+		 *
+		 * XXX: if user code wrote 0 to FS and cleared the base
+		 * address itself, we won't notice and we'll incorrectly
+		 * restore the prior base address next time we reschdule
+		 * the process.
 		 */
 		if (fsindex)
 			prev->fs = 0;
 	}
-	/* when next process has a 64bit base use it */
 	if (next->fs)
 		wrmsrl(MSR_FS_BASE, next->fs);
 	prev->fsindex = fsindex;
 
 	if (unlikely(gsindex | next->gsindex | prev->gs)) {
 		load_gs_index(next->gsindex);
+
+		/* This works (and fails) the same way as fsindex above. */
 		if (gsindex)
 			prev->gs = 0;
 	}
```
