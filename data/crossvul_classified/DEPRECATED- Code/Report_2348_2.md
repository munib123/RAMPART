# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2348_2
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2348_2`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 22-62 of the vulnerable file.

#ifdef CONFIG_X86_64
asmlinkage void double_fault(void);
#endif
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void async_page_fault(void);
asmlinkage void spurious_interrupt_bug(void);
asmlinkage void coprocessor_error(void);
asmlinkage void alignment_check(void);
#ifdef CONFIG_X86_MCE
asmlinkage void machine_check(void);
#endif /* CONFIG_X86_MCE */
asmlinkage void simd_coprocessor_error(void);

#ifdef CONFIG_TRACING
asmlinkage void trace_page_fault(void);
#define trace_divide_error divide_error
#define trace_bounds bounds
#define trace_invalid_op invalid_op
#define trace_device_not_available device_not_available
#define trace_coprocessor_segment_overrun coprocessor_segment_overrun
#define trace_invalid_TSS invalid_TSS
#define trace_segment_not_present segment_not_present
#define trace_general_protection general_protection
#define trace_spurious_interrupt_bug spurious_interrupt_bug
#define trace_coprocessor_error coprocessor_error
#define trace_alignment_check alignment_check
#define trace_simd_coprocessor_error simd_coprocessor_error
#define trace_async_page_fault async_page_fault
#endif

dotraplinkage void do_divide_error(struct pt_regs *, long);
dotraplinkage void do_debug(struct pt_regs *, long);
dotraplinkage void do_nmi(struct pt_regs *, long);
dotraplinkage void do_int3(struct pt_regs *, long);
dotraplinkage void do_overflow(struct pt_regs *, long);
dotraplinkage void do_bounds(struct pt_regs *, long);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,7 @@
 
 #ifdef CONFIG_TRACING
 asmlinkage void trace_page_fault(void);
+#define trace_stack_segment stack_segment
 #define trace_divide_error divide_error
 #define trace_bounds bounds
 #define trace_invalid_op invalid_op
```
