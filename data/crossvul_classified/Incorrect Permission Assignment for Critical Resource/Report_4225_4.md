# CrossVul Fix Pair: Incorrect Default Permissions in c
**Pair ID:** 4225_4
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-276
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4225_4`)

## Vulnerability Information & PoC

## Description
Incorrect Default Permissions - During installation, installed file permissions are set to allow anyone to modify those files.

## Vulnerable Code
```c
Lines 305-358 of the vulnerable file.

void arch_setup_new_exec(void)
{
	/* If cpuid was previously disabled for this task, re-enable it. */
	if (test_thread_flag(TIF_NOCPUID))
		enable_cpuid();

	/*
	 * Don't inherit TIF_SSBD across exec boundary when
	 * PR_SPEC_DISABLE_NOEXEC is used.
	 */
	if (test_thread_flag(TIF_SSBD) &&
	    task_spec_ssb_noexec(current)) {
		clear_thread_flag(TIF_SSBD);
		task_clear_spec_ssb_disable(current);
		task_clear_spec_ssb_noexec(current);
		speculation_ctrl_update(task_thread_info(current)->flags);
	}
}

#ifdef CONFIG_X86_IOPL_IOPERM
static inline void tss_invalidate_io_bitmap(struct tss_struct *tss)
{
	/*
	 * Invalidate the I/O bitmap by moving io_bitmap_base outside the
	 * TSS limit so any subsequent I/O access from user space will
	 * trigger a #GP.
	 *
	 * This is correct even when VMEXIT rewrites the TSS limit
	 * to 0x67 as the only requirement is that the base points
	 * outside the limit.
	 */
	tss->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET_INVALID;
}

static inline void switch_to_bitmap(unsigned long tifp)
{
	/*
	 * Invalidate I/O bitmap if the previous task used it. This prevents
	 * any possible leakage of an active I/O bitmap.
	 *
	 * If the next task has an I/O bitmap it will handle it on exit to
	 * user mode.
	 */
	if (tifp & _TIF_IO_BITMAP)
		tss_invalidate_io_bitmap(this_cpu_ptr(&cpu_tss_rw));
}

static void tss_copy_io_bitmap(struct tss_struct *tss, struct io_bitmap *iobm)
{
	/*
	 * Copy at least the byte range of the incoming tasks bitmap which
	 * covers the permitted I/O ports.
	 *
	 * If the previous task which used an I/O bitmap had more bits
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -322,20 +322,6 @@
 }
 
 #ifdef CONFIG_X86_IOPL_IOPERM
-static inline void tss_invalidate_io_bitmap(struct tss_struct *tss)
-{
-	/*
-	 * Invalidate the I/O bitmap by moving io_bitmap_base outside the
-	 * TSS limit so any subsequent I/O access from user space will
-	 * trigger a #GP.
-	 *
-	 * This is correct even when VMEXIT rewrites the TSS limit
-	 * to 0x67 as the only requirement is that the base points
-	 * outside the limit.
-	 */
-	tss->x86_tss.io_bitmap_base = IO_BITMAP_OFFSET_INVALID;
-}
-
 static inline void switch_to_bitmap(unsigned long tifp)
 {
 	/*
@@ -346,7 +332,7 @@
 	 * user mode.
 	 */
 	if (tifp & _TIF_IO_BITMAP)
-		tss_invalidate_io_bitmap(this_cpu_ptr(&cpu_tss_rw));
+		tss_invalidate_io_bitmap();
 }
 
 static void tss_copy_io_bitmap(struct tss_struct *tss, struct io_bitmap *iobm)
@@ -380,7 +366,7 @@
 	u16 *base = &tss->x86_tss.io_bitmap_base;
 
 	if (!test_thread_flag(TIF_IO_BITMAP)) {
-		tss_invalidate_io_bitmap(tss);
+		native_tss_invalidate_io_bitmap();
 		return;
 	}
 
```
