# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3486_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3486_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 770-810 of the vulnerable file.

	for (idx = 0; idx <= armpmu->num_events; ++idx) {
		struct perf_event *event = cpuc->events[idx];
		struct hw_perf_event *hwc;

		if (!test_bit(idx, cpuc->active_mask))
			continue;

		/*
		 * We have a single interrupt for all counters. Check that
		 * each counter has overflowed before we process it.
		 */
		if (!armv7_pmnc_counter_has_overflowed(pmnc, idx))
			continue;

		hwc = &event->hw;
		armpmu_event_update(event, hwc, idx, 1);
		data.period = event->hw.last_period;
		if (!armpmu_event_set_period(event, hwc, idx))
			continue;

		if (perf_event_overflow(event, 0, &data, regs))
			armpmu->disable(hwc, idx);
	}

	/*
	 * Handle the pending perf events.
	 *
	 * Note: this call *must* be run with interrupts disabled. For
	 * platforms that can have the PMU interrupts raised as an NMI, this
	 * will not work.
	 */
	irq_work_run();

	return IRQ_HANDLED;
}

static void armv7pmu_start(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pmu_lock, flags);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -787,7 +787,7 @@
 		if (!armpmu_event_set_period(event, hwc, idx))
 			continue;
 
-		if (perf_event_overflow(event, 0, &data, regs))
+		if (perf_event_overflow(event, &data, regs))
 			armpmu->disable(hwc, idx);
 	}
 
```
