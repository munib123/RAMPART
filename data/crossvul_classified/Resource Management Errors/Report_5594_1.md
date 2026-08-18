# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5594_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5594_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1389-1429 of the vulnerable file.

	host_tsc_clocksource = kvm_get_time_and_clockread(
					&ka->master_kernel_ns,
					&ka->master_cycle_now);

	ka->use_master_clock = host_tsc_clocksource & vcpus_matched;

	if (ka->use_master_clock)
		atomic_set(&kvm_guest_has_master_clock, 1);

	vclock_mode = pvclock_gtod_data.clock.vclock_mode;
	trace_kvm_update_master_clock(ka->use_master_clock, vclock_mode,
					vcpus_matched);
#endif
}

static int kvm_guest_time_update(struct kvm_vcpu *v)
{
	unsigned long flags, this_tsc_khz;
	struct kvm_vcpu_arch *vcpu = &v->arch;
	struct kvm_arch *ka = &v->kvm->arch;
	void *shared_kaddr;
	s64 kernel_ns, max_kernel_ns;
	u64 tsc_timestamp, host_tsc;
	struct pvclock_vcpu_time_info *guest_hv_clock;
	u8 pvclock_flags;
	bool use_master_clock;

	kernel_ns = 0;
	host_tsc = 0;

	/*
	 * If the host uses TSC clock, then passthrough TSC as stable
	 * to the guest.
	 */
	spin_lock(&ka->pvclock_gtod_sync_lock);
	use_master_clock = ka->use_master_clock;
	if (use_master_clock) {
		host_tsc = ka->master_cycle_now;
		kernel_ns = ka->master_kernel_ns;
	}
	spin_unlock(&ka->pvclock_gtod_sync_lock);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1406,10 +1406,9 @@
 	unsigned long flags, this_tsc_khz;
 	struct kvm_vcpu_arch *vcpu = &v->arch;
 	struct kvm_arch *ka = &v->kvm->arch;
-	void *shared_kaddr;
 	s64 kernel_ns, max_kernel_ns;
 	u64 tsc_timestamp, host_tsc;
-	struct pvclock_vcpu_time_info *guest_hv_clock;
+	struct pvclock_vcpu_time_info guest_hv_clock;
 	u8 pvclock_flags;
 	bool use_master_clock;
 
@@ -1463,7 +1462,7 @@
 
 	local_irq_restore(flags);
 
-	if (!vcpu->time_page)
+	if (!vcpu->pv_time_enabled)
 		return 0;
 
 	/*
@@ -1525,12 +1524,12 @@
 	 */
 	vcpu->hv_clock.version += 2;
 
-	shared_kaddr = kmap_atomic(vcpu->time_page);
-
-	guest_hv_clock = shared_kaddr + vcpu->time_offset;
+	if (unlikely(kvm_read_guest_cached(v->kvm, &vcpu->pv_time,
+		&guest_hv_clock, sizeof(guest_hv_clock))))
+		return 0;
 
 	/* retain PVCLOCK_GUEST_STOPPED if set in guest copy */
-	pvclock_flags = (guest_hv_clock->flags & PVCLOCK_GUEST_STOPPED);
+	pvclock_flags = (guest_hv_clock.flags & PVCLOCK_GUEST_STOPPED);
 
 	if (vcpu->pvclock_set_guest_stopped_request) {
 		pvclock_flags |= PVCLOCK_GUEST_STOPPED;
@@ -1543,12 +1542,9 @@
 
 	vcpu->hv_clock.flags = pvclock_flags;
 
-	memcpy(shared_kaddr + vcpu->time_offset, &vcpu->hv_clock,
-	       sizeof(vcpu->hv_clock));
-
-	kunmap_atomic(shared_kaddr);
-
-	mark_page_dirty(v->kvm, vcpu->time >> PAGE_SHIFT);
+	kvm_write_guest_cached(v->kvm, &vcpu->pv_time,
+				&vcpu->hv_clock,
+				sizeof(vcpu->hv_clock));
 	return 0;
 }
 
@@ -1837,10 +1833,7 @@
 
 static void kvmclock_reset(struct kvm_vcpu *vcpu)
 {
-	if (vcpu->arch.time_page) {
-		kvm_release_page_dirty(vcpu->arch.time_page);
-		vcpu->arch.time_page = NULL;
-	}
+	vcpu->arch.pv_time_enabled = false;
 }
 
 static void accumulate_steal_time(struct kvm_vcpu *vcpu)
@@ -1947,6 +1940,7 @@
 		break;
 	case MSR_KVM_SYSTEM_TIME_NEW:
 	case MSR_KVM_SYSTEM_TIME: {
+		u64 gpa_offset;
 		kvmclock_reset(vcpu);
 
 		vcpu->arch.time = data;
@@ -1956,19 +1950,17 @@
 		if (!(data & 1))
 			break;
 
-		/* ...but clean it before doing the actual write */
-		vcpu->arch.time_offset = data & ~(PAGE_MASK | 1);
+		gpa_offset = data & ~(PAGE_MASK | 1);
 
 		/* Check that the address is 32-byte aligned. */
-		if (vcpu->arch.time_offset &
-				(sizeof(struct pvclock_vcpu_time_info) - 1))
+		if (gpa_offset & (sizeof(struct pvclock_vcpu_time_info) - 1))
 			break;
 
-		vcpu->arch.time_page =
-				gfn_to_page(vcpu->kvm, data >> PAGE_SHIFT);
-
-		if (is_error_page(vcpu->arch.time_page))
-			vcpu->arch.time_page = NULL;
+		if (kvm_gfn_to_hva_cache_init(vcpu->kvm,
+		     &vcpu->arch.pv_time, data & ~1ULL))
+			vcpu->arch.pv_time_enabled = false;
+		else
+			vcpu->arch.pv_time_enabled = true;
 
 		break;
 	}
@@ -2972,7 +2964,7 @@
  */
 static int kvm_set_guest_paused(struct kvm_vcpu *vcpu)
 {
-	if (!vcpu->arch.time_page)
+	if (!vcpu->arch.pv_time_enabled)
 		return -EINVAL;
 	vcpu->arch.pvclock_set_guest_stopped_request = true;
 	kvm_make_request(KVM_REQ_CLOCK_UPDATE, vcpu);
@@ -6723,6 +6715,7 @@
 		goto fail_free_wbinvd_dirty_mask;
 
 	vcpu->arch.ia32_tsc_adjust_msr = 0x0;
+	vcpu->arch.pv_time_enabled = false;
 	kvm_async_pf_hash_reset(vcpu);
 	kvm_pmu_init(vcpu);
 
```
