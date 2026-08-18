# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 118_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `118_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 114-154 of the vulnerable file.

#else
	REG_OFFSET_NAME(mq),
#endif
	REG_OFFSET_NAME(trap),
	REG_OFFSET_NAME(dar),
	REG_OFFSET_NAME(dsisr),
	REG_OFFSET_END,
};

#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
static void flush_tmregs_to_thread(struct task_struct *tsk)
{
	/*
	 * If task is not current, it will have been flushed already to
	 * it's thread_struct during __switch_to().
	 *
	 * A reclaim flushes ALL the state or if not in TM save TM SPRs
	 * in the appropriate thread structures from live.
	 */

	if (tsk != current)
		return;

	if (MSR_TM_SUSPENDED(mfmsr())) {
		tm_reclaim_current(TM_CAUSE_SIGNAL);
	} else {
		tm_enable();
		tm_save_sprs(&(tsk->thread));
	}
}
#else
static inline void flush_tmregs_to_thread(struct task_struct *tsk) { }
#endif

/**
 * regs_query_register_offset() - query register offset from its name
 * @name:	the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -131,7 +131,7 @@
 	 * in the appropriate thread structures from live.
 	 */
 
-	if (tsk != current)
+	if ((!cpu_has_feature(CPU_FTR_TM)) || (tsk != current))
 		return;
 
 	if (MSR_TM_SUSPENDED(mfmsr())) {
```
