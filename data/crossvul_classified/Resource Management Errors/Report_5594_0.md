# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5594_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5594_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 397-438 of the vulnerable file.

	struct kvm_queued_interrupt {
		bool pending;
		bool soft;
		u8 nr;
	} interrupt;

	int halt_request; /* real mode on Intel only */

	int cpuid_nent;
	struct kvm_cpuid_entry2 cpuid_entries[KVM_MAX_CPUID_ENTRIES];
	/* emulate context */

	struct x86_emulate_ctxt emulate_ctxt;
	bool emulate_regs_need_sync_to_vcpu;
	bool emulate_regs_need_sync_from_vcpu;
	int (*complete_userspace_io)(struct kvm_vcpu *vcpu);

	gpa_t time;
	struct pvclock_vcpu_time_info hv_clock;
	unsigned int hw_tsc_khz;
	unsigned int time_offset;
	struct page *time_page;
	/* set guest stopped flag in pvclock flags field */
	bool pvclock_set_guest_stopped_request;

	struct {
		u64 msr_val;
		u64 last_steal;
		u64 accum_steal;
		struct gfn_to_hva_cache stime;
		struct kvm_steal_time steal;
	} st;

	u64 last_guest_tsc;
	u64 last_kernel_ns;
	u64 last_host_tsc;
	u64 tsc_offset_adjustment;
	u64 this_tsc_nsec;
	u64 this_tsc_write;
	u8  this_tsc_generation;
	bool tsc_catchup;
	bool tsc_always_catchup;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -414,8 +414,8 @@
 	gpa_t time;
 	struct pvclock_vcpu_time_info hv_clock;
 	unsigned int hw_tsc_khz;
-	unsigned int time_offset;
-	struct page *time_page;
+	struct gfn_to_hva_cache pv_time;
+	bool pv_time_enabled;
 	/* set guest stopped flag in pvclock flags field */
 	bool pvclock_set_guest_stopped_request;
 
```
