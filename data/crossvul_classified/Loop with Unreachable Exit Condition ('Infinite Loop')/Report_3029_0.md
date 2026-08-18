# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 3029_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3029_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 48-88 of the vulnerable file.


struct arch_timer_erratum_workaround {
	enum arch_timer_erratum_match_type match_type;
	const void *id;
	const char *desc;
	u32 (*read_cntp_tval_el0)(void);
	u32 (*read_cntv_tval_el0)(void);
	u64 (*read_cntvct_el0)(void);
	int (*set_next_event_phys)(unsigned long, struct clock_event_device *);
	int (*set_next_event_virt)(unsigned long, struct clock_event_device *);
};

DECLARE_PER_CPU(const struct arch_timer_erratum_workaround *,
		timer_unstable_counter_workaround);

#define arch_timer_reg_read_stable(reg)					\
({									\
	u64 _val;							\
	if (needs_unstable_timer_counter_workaround()) {		\
		const struct arch_timer_erratum_workaround *wa;		\
		preempt_disable();					\
		wa = __this_cpu_read(timer_unstable_counter_workaround); \
		if (wa && wa->read_##reg)				\
			_val = wa->read_##reg();			\
		else							\
			_val = read_sysreg(reg);			\
		preempt_enable();					\
	} else {							\
		_val = read_sysreg(reg);				\
	}								\
	_val;								\
})

/*
 * These register accessors are marked inline so the compiler can
 * nicely work out which register we want, and chuck away the rest of
 * the code.
 */
static __always_inline
void arch_timer_reg_write_cp15(int access, enum arch_timer_reg reg, u32 val)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,13 +65,13 @@
 	u64 _val;							\
 	if (needs_unstable_timer_counter_workaround()) {		\
 		const struct arch_timer_erratum_workaround *wa;		\
-		preempt_disable();					\
+		preempt_disable_notrace();				\
 		wa = __this_cpu_read(timer_unstable_counter_workaround); \
 		if (wa && wa->read_##reg)				\
 			_val = wa->read_##reg();			\
 		else							\
 			_val = read_sysreg(reg);			\
-		preempt_enable();					\
+		preempt_enable_notrace();				\
 	} else {							\
 		_val = read_sysreg(reg);				\
 	}								\
```
