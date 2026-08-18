# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2956_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2956_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 123-165 of the vulnerable file.

	DEBUG_LOCKS_WARN_ON(preemptible());
}

static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
	if (this_cpu_read(cpu_tlbstate.state) == TLBSTATE_OK)
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_LAZY);
}

static inline int init_new_context(struct task_struct *tsk,
				   struct mm_struct *mm)
{
	#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS
	if (cpu_feature_enabled(X86_FEATURE_OSPKE)) {
		/* pkey 0 is the default and always allocated */
		mm->context.pkey_allocation_map = 0x1;
		/* -1 means unallocated or invalid */
		mm->context.execute_only_pkey = -1;
	}
	#endif
	init_new_context_ldt(tsk, mm);

	return 0;
}
static inline void destroy_context(struct mm_struct *mm)
{
	destroy_context_ldt(mm);
}

extern void switch_mm(struct mm_struct *prev, struct mm_struct *next,
		      struct task_struct *tsk);

extern void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			       struct task_struct *tsk);
#define switch_mm_irqs_off switch_mm_irqs_off

#define activate_mm(prev, next)			\
do {						\
	paravirt_activate_mm((prev), (next));	\
	switch_mm((prev), (next), NULL);	\
} while (0);

#ifdef CONFIG_X86_32
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,9 +140,7 @@
 		mm->context.execute_only_pkey = -1;
 	}
 	#endif
-	init_new_context_ldt(tsk, mm);
-
-	return 0;
+	return init_new_context_ldt(tsk, mm);
 }
 static inline void destroy_context(struct mm_struct *mm)
 {
```
