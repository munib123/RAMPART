# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3486_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3486_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 830-870 of the vulnerable file.

		/* This can occur if the event is disabled right on a PMC overflow. */
		wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);
		return;
	}

	event = cpuc->event[j];

	if (unlikely(!event)) {
		/* This should never occur! */
		irq_err_count++;
		pr_warning("PMI: No event at index %d!\n", idx);
		wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);
		return;
	}

	hwc = &event->hw;
	alpha_perf_event_update(event, hwc, idx, alpha_pmu->pmc_max_period[idx]+1);
	data.period = event->hw.last_period;

	if (alpha_perf_event_set_period(event, hwc, idx)) {
		if (perf_event_overflow(event, 1, &data, regs)) {
			/* Interrupts coming too quickly; "throttle" the
			 * counter, i.e., disable it for a little while.
			 */
			alpha_pmu_stop(event, 0);
		}
	}
	wrperfmon(PERFMON_CMD_ENABLE, cpuc->idx_mask);

	return;
}



/*
 * Init call to initialise performance events at kernel startup.
 */
int __init init_hw_perf_events(void)
{
	pr_info("Performance events: ");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -847,7 +847,7 @@
 	data.period = event->hw.last_period;
 
 	if (alpha_perf_event_set_period(event, hwc, idx)) {
-		if (perf_event_overflow(event, 1, &data, regs)) {
+		if (perf_event_overflow(event, &data, regs)) {
 			/* Interrupts coming too quickly; "throttle" the
 			 * counter, i.e., disable it for a little while.
 			 */
```
