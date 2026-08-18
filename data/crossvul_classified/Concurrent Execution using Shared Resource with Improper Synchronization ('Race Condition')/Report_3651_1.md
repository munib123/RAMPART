# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3651_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3651_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 428-468 of the vulnerable file.

#ifdef CONFIG_MMU

#ifndef CONFIG_TRANSPARENT_HUGEPAGE
static inline int pmd_trans_huge(pmd_t pmd)
{
	return 0;
}
static inline int pmd_trans_splitting(pmd_t pmd)
{
	return 0;
}
#ifndef __HAVE_ARCH_PMD_WRITE
static inline int pmd_write(pmd_t pmd)
{
	BUG();
	return 0;
}
#endif /* __HAVE_ARCH_PMD_WRITE */
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/*
 * This function is meant to be used by sites walking pagetables with
 * the mmap_sem hold in read mode to protect against MADV_DONTNEED and
 * transhuge page faults. MADV_DONTNEED can convert a transhuge pmd
 * into a null pmd and the transhuge page fault can convert a null pmd
 * into an hugepmd or into a regular pmd (if the hugepage allocation
 * fails). While holding the mmap_sem in read mode the pmd becomes
 * stable and stops changing under us only if it's not null and not a
 * transhuge pmd. When those races occurs and this function makes a
 * difference vs the standard pmd_none_or_clear_bad, the result is
 * undefined so behaving like if the pmd was none is safe (because it
 * can return none anyway). The compiler level barrier() is critically
 * important to compute the two checks atomically on the same pmdval.
 */
static inline int pmd_none_or_trans_huge_or_clear_bad(pmd_t *pmd)
{
	/* depend on compiler for an atomic pmd read */
	pmd_t pmdval = *pmd;
	/*
	 * The barrier will stabilize the pmdval in a register or on
	 * the stack so that it will stop changing under the code.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -445,6 +445,18 @@
 #endif /* __HAVE_ARCH_PMD_WRITE */
 #endif /* CONFIG_TRANSPARENT_HUGEPAGE */
 
+#ifndef pmd_read_atomic
+static inline pmd_t pmd_read_atomic(pmd_t *pmdp)
+{
+	/*
+	 * Depend on compiler for an atomic pmd read. NOTE: this is
+	 * only going to work, if the pmdval_t isn't larger than
+	 * an unsigned long.
+	 */
+	return *pmdp;
+}
+#endif
+
 /*
  * This function is meant to be used by sites walking pagetables with
  * the mmap_sem hold in read mode to protect against MADV_DONTNEED and
@@ -458,11 +470,17 @@
  * undefined so behaving like if the pmd was none is safe (because it
  * can return none anyway). The compiler level barrier() is critically
  * important to compute the two checks atomically on the same pmdval.
+ *
+ * For 32bit kernels with a 64bit large pmd_t this automatically takes
+ * care of reading the pmd atomically to avoid SMP race conditions
+ * against pmd_populate() when the mmap_sem is hold for reading by the
+ * caller (a special atomic read not done by "gcc" as in the generic
+ * version above, is also needed when THP is disabled because the page
+ * fault can populate the pmd from under us).
  */
 static inline int pmd_none_or_trans_huge_or_clear_bad(pmd_t *pmd)
 {
-	/* depend on compiler for an atomic pmd read */
-	pmd_t pmdval = *pmd;
+	pmd_t pmdval = pmd_read_atomic(pmd);
 	/*
 	 * The barrier will stabilize the pmdval in a register or on
 	 * the stack so that it will stop changing under the code.
```
