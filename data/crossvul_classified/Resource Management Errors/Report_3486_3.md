# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3486_3
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3486_3`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 234-274 of the vulnerable file.


	perf_sample_data_init(&data, 0);

	cpuc = &__get_cpu_var(cpu_hw_events);
	for (idx = 0; idx <= armpmu->num_events; ++idx) {
		struct perf_event *event = cpuc->events[idx];
		struct hw_perf_event *hwc;

		if (!test_bit(idx, cpuc->active_mask))
			continue;

		if (!xscale1_pmnc_counter_has_overflowed(pmnc, idx))
			continue;

		hwc = &event->hw;
		armpmu_event_update(event, hwc, idx, 1);
		data.period = event->hw.last_period;
		if (!armpmu_event_set_period(event, hwc, idx))
			continue;

		if (perf_event_overflow(event, 0, &data, regs))
			armpmu->disable(hwc, idx);
	}

	irq_work_run();

	/*
	 * Re-enable the PMU.
	 */
	pmnc = xscale1pmu_read_pmnc() | XSCALE_PMU_ENABLE;
	xscale1pmu_write_pmnc(pmnc);

	return IRQ_HANDLED;
}

static void
xscale1pmu_enable_event(struct hw_perf_event *hwc, int idx)
{
	unsigned long val, mask, evt, flags;

	switch (idx) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -251,7 +251,7 @@
 		if (!armpmu_event_set_period(event, hwc, idx))
 			continue;
 
-		if (perf_event_overflow(event, 0, &data, regs))
+		if (perf_event_overflow(event, &data, regs))
 			armpmu->disable(hwc, idx);
 	}
 
@@ -583,7 +583,7 @@
 		if (!armpmu_event_set_period(event, hwc, idx))
 			continue;
 
-		if (perf_event_overflow(event, 0, &data, regs))
+		if (perf_event_overflow(event, &data, regs))
 			armpmu->disable(hwc, idx);
 	}
 
```
