# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2602_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2602_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 580-620 of the vulnerable file.

	u64 idx;

	if (!kvm_arm_pmu_v3_ready(vcpu))
		return trap_raz_wi(vcpu, p, r);

	if (r->CRn == 9 && r->CRm == 13) {
		if (r->Op2 == 2) {
			/* PMXEVCNTR_EL0 */
			if (pmu_access_event_counter_el0_disabled(vcpu))
				return false;

			idx = vcpu_sys_reg(vcpu, PMSELR_EL0)
			      & ARMV8_PMU_COUNTER_MASK;
		} else if (r->Op2 == 0) {
			/* PMCCNTR_EL0 */
			if (pmu_access_cycle_counter_el0_disabled(vcpu))
				return false;

			idx = ARMV8_PMU_CYCLE_IDX;
		} else {
			BUG();
		}
	} else if (r->CRn == 14 && (r->CRm & 12) == 8) {
		/* PMEVCNTRn_EL0 */
		if (pmu_access_event_counter_el0_disabled(vcpu))
			return false;

		idx = ((r->CRm & 3) << 3) | (r->Op2 & 7);
	} else {
		BUG();
	}

	if (!pmu_counter_idx_valid(vcpu, idx))
		return false;

	if (p->is_write) {
		if (pmu_access_el0_disabled(vcpu))
			return false;

		kvm_pmu_set_counter_value(vcpu, idx, p->regval);
	} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -597,8 +597,14 @@
 
 			idx = ARMV8_PMU_CYCLE_IDX;
 		} else {
-			BUG();
+			return false;
 		}
+	} else if (r->CRn == 0 && r->CRm == 9) {
+		/* PMCCNTR */
+		if (pmu_access_event_counter_el0_disabled(vcpu))
+			return false;
+
+		idx = ARMV8_PMU_CYCLE_IDX;
 	} else if (r->CRn == 14 && (r->CRm & 12) == 8) {
 		/* PMEVCNTRn_EL0 */
 		if (pmu_access_event_counter_el0_disabled(vcpu))
@@ -606,7 +612,7 @@
 
 		idx = ((r->CRm & 3) << 3) | (r->Op2 & 7);
 	} else {
-		BUG();
+		return false;
 	}
 
 	if (!pmu_counter_idx_valid(vcpu, idx))
```
