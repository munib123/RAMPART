# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3486_7
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3486_7`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 510-550 of the vulnerable file.


	if (!validate_event(&fake_cpuc, event))
		return -ENOSPC;

	return 0;
}

/* This is needed by specific irq handlers in perf_event_*.c */
static void
handle_associated_event(struct cpu_hw_events *cpuc,
	int idx, struct perf_sample_data *data, struct pt_regs *regs)
{
	struct perf_event *event = cpuc->events[idx];
	struct hw_perf_event *hwc = &event->hw;

	mipspmu_event_update(event, hwc, idx);
	data->period = event->hw.last_period;
	if (!mipspmu_event_set_period(event, hwc, idx))
		return;

	if (perf_event_overflow(event, 0, data, regs))
		mipspmu->disable_event(idx);
}

#include "perf_event_mipsxx.c"

/* Callchain handling code. */

/*
 * Leave userspace callchain empty for now. When we find a way to trace
 * the user stack callchains, we add here.
 */
void perf_callchain_user(struct perf_callchain_entry *entry,
		    struct pt_regs *regs)
{
}

static void save_raw_perf_callchain(struct perf_callchain_entry *entry,
	unsigned long reg29)
{
	unsigned long *sp = (unsigned long *)reg29;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -527,7 +527,7 @@
 	if (!mipspmu_event_set_period(event, hwc, idx))
 		return;
 
-	if (perf_event_overflow(event, 0, data, regs))
+	if (perf_event_overflow(event, data, regs))
 		mipspmu->disable_event(idx);
 }
 
```
