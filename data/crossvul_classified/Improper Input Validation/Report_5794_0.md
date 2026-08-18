# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5794_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5794_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1675-1715 of the vulnerable file.

	 * KVM_APIC_PV_EOI_PENDING is set, KVM_PV_EOI_ENABLED is unset:
	 * 	-> host enabled PV EOI, guest executed EOI.
	 */
	BUG_ON(!pv_eoi_enabled(vcpu));
	pending = pv_eoi_get_pending(vcpu);
	/*
	 * Clear pending bit in any case: it will be set again on vmentry.
	 * While this might not be ideal from performance point of view,
	 * this makes sure pv eoi is only enabled when we know it's safe.
	 */
	pv_eoi_clr_pending(vcpu);
	if (pending)
		return;
	vector = apic_set_eoi(apic);
	trace_kvm_pv_eoi(apic, vector);
}

void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu)
{
	u32 data;
	void *vapic;

	if (test_bit(KVM_APIC_PV_EOI_PENDING, &vcpu->arch.apic_attention))
		apic_sync_pv_eoi_from_guest(vcpu, vcpu->arch.apic);

	if (!test_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention))
		return;

	vapic = kmap_atomic(vcpu->arch.apic->vapic_page);
	data = *(u32 *)(vapic + offset_in_page(vcpu->arch.apic->vapic_addr));
	kunmap_atomic(vapic);

	apic_set_tpr(vcpu->arch.apic, data & 0xff);
}

/*
 * apic_sync_pv_eoi_to_guest - called before vmentry
 *
 * Detect whether it's safe to enable PV EOI and
 * if yes do so.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1692,7 +1692,6 @@
 void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu)
 {
 	u32 data;
-	void *vapic;
 
 	if (test_bit(KVM_APIC_PV_EOI_PENDING, &vcpu->arch.apic_attention))
 		apic_sync_pv_eoi_from_guest(vcpu, vcpu->arch.apic);
@@ -1700,9 +1699,8 @@
 	if (!test_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention))
 		return;
 
-	vapic = kmap_atomic(vcpu->arch.apic->vapic_page);
-	data = *(u32 *)(vapic + offset_in_page(vcpu->arch.apic->vapic_addr));
-	kunmap_atomic(vapic);
+	kvm_read_guest_cached(vcpu->kvm, &vcpu->arch.apic->vapic_cache, &data,
+				sizeof(u32));
 
 	apic_set_tpr(vcpu->arch.apic, data & 0xff);
 }
@@ -1738,7 +1736,6 @@
 	u32 data, tpr;
 	int max_irr, max_isr;
 	struct kvm_lapic *apic = vcpu->arch.apic;
-	void *vapic;
 
 	apic_sync_pv_eoi_to_guest(vcpu, apic);
 
@@ -1754,18 +1751,24 @@
 		max_isr = 0;
 	data = (tpr & 0xff) | ((max_isr & 0xf0) << 8) | (max_irr << 24);
 
-	vapic = kmap_atomic(vcpu->arch.apic->vapic_page);
-	*(u32 *)(vapic + offset_in_page(vcpu->arch.apic->vapic_addr)) = data;
-	kunmap_atomic(vapic);
-}
-
-void kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr)
-{
+	kvm_write_guest_cached(vcpu->kvm, &vcpu->arch.apic->vapic_cache, &data,
+				sizeof(u32));
+}
+
+int kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr)
+{
+	if (vapic_addr) {
+		if (kvm_gfn_to_hva_cache_init(vcpu->kvm,
+					&vcpu->arch.apic->vapic_cache,
+					vapic_addr, sizeof(u32)))
+			return -EINVAL;
+		__set_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
+	} else {
+		__clear_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
+	}
+
 	vcpu->arch.apic->vapic_addr = vapic_addr;
-	if (vapic_addr)
-		__set_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
-	else
-		__clear_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention);
+	return 0;
 }
 
 int kvm_x2apic_msr_write(struct kvm_vcpu *vcpu, u32 msr, u64 data)
```
