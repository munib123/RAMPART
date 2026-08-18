# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1846_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1846_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 305-346 of the vulnerable file.

	 * If there is an event in the counter we are going to use then make
	 * sure it is disabled.
	 */
	event->hw.idx = idx;
	armpmu->disable(hwc, idx);
	hw_events->events[idx] = event;

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
	if (flags & PERF_EF_START)
		armpmu_start(event, PERF_EF_RELOAD);

	/* Propagate our changes to the userspace mapping. */
	perf_event_update_userpage(event);

out:
	perf_pmu_enable(event->pmu);
	return err;
}

static int
validate_event(struct pmu_hw_events *hw_events,
	       struct perf_event *event)
{
	struct arm_pmu *armpmu = to_arm_pmu(event->pmu);
	struct hw_perf_event fake_event = event->hw;
	struct pmu *leader_pmu = event->group_leader->pmu;

	if (is_software_event(event))
		return 1;

	if (event->pmu != leader_pmu || event->state < PERF_EVENT_STATE_OFF)
		return 1;

	if (event->state == PERF_EVENT_STATE_OFF && !event->attr.enable_on_exec)
		return 1;

	return armpmu->get_event_idx(hw_events, &fake_event) >= 0;
}

static int
validate_group(struct perf_event *event)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -322,22 +322,31 @@
 }
 
 static int
-validate_event(struct pmu_hw_events *hw_events,
-	       struct perf_event *event)
-{
-	struct arm_pmu *armpmu = to_arm_pmu(event->pmu);
+validate_event(struct pmu *pmu, struct pmu_hw_events *hw_events,
+				struct perf_event *event)
+{
+	struct arm_pmu *armpmu;
 	struct hw_perf_event fake_event = event->hw;
 	struct pmu *leader_pmu = event->group_leader->pmu;
 
 	if (is_software_event(event))
 		return 1;
 
+	/*
+	 * Reject groups spanning multiple HW PMUs (e.g. CPU + CCI). The
+	 * core perf code won't check that the pmu->ctx == leader->ctx
+	 * until after pmu->event_init(event).
+	 */
+	if (event->pmu != pmu)
+		return 0;
+
 	if (event->pmu != leader_pmu || event->state < PERF_EVENT_STATE_OFF)
 		return 1;
 
 	if (event->state == PERF_EVENT_STATE_OFF && !event->attr.enable_on_exec)
 		return 1;
 
+	armpmu = to_arm_pmu(event->pmu);
 	return armpmu->get_event_idx(hw_events, &fake_event) >= 0;
 }
 
@@ -355,15 +364,15 @@
 	memset(fake_used_mask, 0, sizeof(fake_used_mask));
 	fake_pmu.used_mask = fake_used_mask;
 
-	if (!validate_event(&fake_pmu, leader))
+	if (!validate_event(event->pmu, &fake_pmu, leader))
 		return -EINVAL;
 
 	list_for_each_entry(sibling, &leader->sibling_list, group_entry) {
-		if (!validate_event(&fake_pmu, sibling))
+		if (!validate_event(event->pmu, &fake_pmu, sibling))
 			return -EINVAL;
 	}
 
-	if (!validate_event(&fake_pmu, event))
+	if (!validate_event(event->pmu, &fake_pmu, event))
 		return -EINVAL;
 
 	return 0;
```
