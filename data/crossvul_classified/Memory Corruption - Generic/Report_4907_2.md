# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4907_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4907_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3153-3193 of the vulnerable file.

	print_modules();
	if (irqs_disabled())
		print_irqtrace_events(prev);
#ifdef CONFIG_DEBUG_PREEMPT
	if (in_atomic_preempt_off()) {
		pr_err("Preemption disabled at:");
		print_ip_sym(current->preempt_disable_ip);
		pr_cont("\n");
	}
#endif
	dump_stack();
	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
}

/*
 * Various schedule()-time debugging checks and statistics:
 */
static inline void schedule_debug(struct task_struct *prev)
{
#ifdef CONFIG_SCHED_STACK_END_CHECK
	BUG_ON(task_stack_end_corrupted(prev));
#endif

	if (unlikely(in_atomic_preempt_off())) {
		__schedule_bug(prev);
		preempt_count_set(PREEMPT_DISABLED);
	}
	rcu_sleep_check();

	profile_hit(SCHED_PROFILING, __builtin_return_address(0));

	schedstat_inc(this_rq(), sched_count);
}

/*
 * Pick up the highest-prio task:
 */
static inline struct task_struct *
pick_next_task(struct rq *rq, struct task_struct *prev, struct pin_cookie cookie)
{
	const struct sched_class *class = &fair_sched_class;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3170,7 +3170,8 @@
 static inline void schedule_debug(struct task_struct *prev)
 {
 #ifdef CONFIG_SCHED_STACK_END_CHECK
-	BUG_ON(task_stack_end_corrupted(prev));
+	if (task_stack_end_corrupted(prev))
+		panic("corrupted stack end detected inside scheduler\n");
 #endif
 
 	if (unlikely(in_atomic_preempt_off())) {
```
