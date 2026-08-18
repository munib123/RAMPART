# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3486_4
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3486_4`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 379-419 of the vulnerable file.

{
	if (num < 0)
		num = (ARM_MAX_BRP << 1) - num;
	return (num - 1) >> 1;
}

/*
 * Returns the virtual register number for the address of the
 * breakpoint at index idx.
 */
static long ptrace_hbp_idx_to_num(int idx)
{
	long mid = ARM_MAX_BRP << 1;
	long num = (idx << 1) + 1;
	return num > mid ? mid - num : num;
}

/*
 * Handle hitting a HW-breakpoint.
 */
static void ptrace_hbptriggered(struct perf_event *bp, int unused,
				     struct perf_sample_data *data,
				     struct pt_regs *regs)
{
	struct arch_hw_breakpoint *bkpt = counter_arch_bp(bp);
	long num;
	int i;
	siginfo_t info;

	for (i = 0; i < ARM_MAX_HBP_SLOTS; ++i)
		if (current->thread.debug.hbp[i] == bp)
			break;

	num = (i == ARM_MAX_HBP_SLOTS) ? 0 : ptrace_hbp_idx_to_num(i);

	info.si_signo	= SIGTRAP;
	info.si_errno	= (int)num;
	info.si_code	= TRAP_HWBKPT;
	info.si_addr	= (void __user *)(bkpt->trigger);

	force_sig_info(SIGTRAP, &info, current);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -396,7 +396,7 @@
 /*
  * Handle hitting a HW-breakpoint.
  */
-static void ptrace_hbptriggered(struct perf_event *bp, int unused,
+static void ptrace_hbptriggered(struct perf_event *bp,
 				     struct perf_sample_data *data,
 				     struct pt_regs *regs)
 {
```
