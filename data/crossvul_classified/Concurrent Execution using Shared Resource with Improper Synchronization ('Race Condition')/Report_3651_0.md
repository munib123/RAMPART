# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3651_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3651_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

	       __FILE__, __LINE__, &(e), (e).pte_high, (e).pte_low)
#define pmd_ERROR(e)							\
	printk("%s:%d: bad pmd %p(%016Lx).\n",				\
	       __FILE__, __LINE__, &(e), pmd_val(e))
#define pgd_ERROR(e)							\
	printk("%s:%d: bad pgd %p(%016Lx).\n",				\
	       __FILE__, __LINE__, &(e), pgd_val(e))

/* Rules for using set_pte: the pte being assigned *must* be
 * either not present or in a state where the hardware will
 * not attempt to update the pte.  In places where this is
 * not possible, use pte_get_and_clear to obtain the old pte
 * value and then use set_pte to update it.  -ben
 */
static inline void native_set_pte(pte_t *ptep, pte_t pte)
{
	ptep->pte_high = pte.pte_high;
	smp_wmb();
	ptep->pte_low = pte.pte_low;
}

static inline void native_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	set_64bit((unsigned long long *)(ptep), native_pte_val(pte));
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	set_64bit((unsigned long long *)(pmdp), native_pmd_val(pmd));
}

static inline void native_set_pud(pud_t *pudp, pud_t pud)
{
	set_64bit((unsigned long long *)(pudp), native_pud_val(pud));
}

/*
 * For PTEs and PDEs, we must clear the P-bit first when clearing a page table
 * entry, so clear the bottom half first and enforce ordering with a compiler
 * barrier.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,56 @@
 	smp_wmb();
 	ptep->pte_low = pte.pte_low;
 }
+
+#define pmd_read_atomic pmd_read_atomic
+/*
+ * pte_offset_map_lock on 32bit PAE kernels was reading the pmd_t with
+ * a "*pmdp" dereference done by gcc. Problem is, in certain places
+ * where pte_offset_map_lock is called, concurrent page faults are
+ * allowed, if the mmap_sem is hold for reading. An example is mincore
+ * vs page faults vs MADV_DONTNEED. On the page fault side
+ * pmd_populate rightfully does a set_64bit, but if we're reading the
+ * pmd_t with a "*pmdp" on the mincore side, a SMP race can happen
+ * because gcc will not read the 64bit of the pmd atomically. To fix
+ * this all places running pmd_offset_map_lock() while holding the
+ * mmap_sem in read mode, shall read the pmdp pointer using this
+ * function to know if the pmd is null nor not, and in turn to know if
+ * they can run pmd_offset_map_lock or pmd_trans_huge or other pmd
+ * operations.
+ *
+ * Without THP if the mmap_sem is hold for reading, the
+ * pmd can only transition from null to not null while pmd_read_atomic runs.
+ * So there's no need of literally reading it atomically.
+ *
+ * With THP if the mmap_sem is hold for reading, the pmd can become
+ * THP or null or point to a pte (and in turn become "stable") at any
+ * time under pmd_read_atomic, so it's mandatory to read it atomically
+ * with cmpxchg8b.
+ */
+#ifndef CONFIG_TRANSPARENT_HUGEPAGE
+static inline pmd_t pmd_read_atomic(pmd_t *pmdp)
+{
+	pmdval_t ret;
+	u32 *tmp = (u32 *)pmdp;
+
+	ret = (pmdval_t) (*tmp);
+	if (ret) {
+		/*
+		 * If the low part is null, we must not read the high part
+		 * or we can end up with a partial pmd.
+		 */
+		smp_rmb();
+		ret |= ((pmdval_t)*(tmp + 1)) << 32;
+	}
+
+	return (pmd_t) { ret };
+}
+#else /* CONFIG_TRANSPARENT_HUGEPAGE */
+static inline pmd_t pmd_read_atomic(pmd_t *pmdp)
+{
+	return (pmd_t) { atomic64_read((atomic64_t *)pmdp) };
+}
+#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
 
 static inline void native_set_pte_atomic(pte_t *ptep, pte_t pte)
 {
```
