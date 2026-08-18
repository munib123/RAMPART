# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5797_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5797_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 126-166 of the vulnerable file.

	apic_set_reg(apic, APIC_SPIV, val);
}

static inline int apic_enabled(struct kvm_lapic *apic)
{
	return kvm_apic_sw_enabled(apic) &&	kvm_apic_hw_enabled(apic);
}

#define LVT_MASK	\
	(APIC_LVT_MASKED | APIC_SEND_PENDING | APIC_VECTOR_MASK)

#define LINT_MASK	\
	(LVT_MASK | APIC_MODE_MASK | APIC_INPUT_POLARITY | \
	 APIC_LVT_REMOTE_IRR | APIC_LVT_LEVEL_TRIGGER)

static inline int kvm_apic_id(struct kvm_lapic *apic)
{
	return (kvm_apic_get_reg(apic, APIC_ID) >> 24) & 0xff;
}

static void recalculate_apic_map(struct kvm *kvm)
{
	struct kvm_apic_map *new, *old = NULL;
	struct kvm_vcpu *vcpu;
	int i;

	new = kzalloc(sizeof(struct kvm_apic_map), GFP_KERNEL);

	mutex_lock(&kvm->arch.apic_map_lock);

	if (!new)
		goto out;

	new->ldr_bits = 8;
	/* flat mode is default */
	new->cid_shift = 8;
	new->cid_mask = 0;
	new->lid_mask = 0xff;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvm_lapic *apic = vcpu->arch.apic;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -143,6 +143,8 @@
 	return (kvm_apic_get_reg(apic, APIC_ID) >> 24) & 0xff;
 }
 
+#define KVM_X2APIC_CID_BITS 0
+
 static void recalculate_apic_map(struct kvm *kvm)
 {
 	struct kvm_apic_map *new, *old = NULL;
@@ -180,7 +182,8 @@
 		if (apic_x2apic_mode(apic)) {
 			new->ldr_bits = 32;
 			new->cid_shift = 16;
-			new->cid_mask = new->lid_mask = 0xffff;
+			new->cid_mask = (1 << KVM_X2APIC_CID_BITS) - 1;
+			new->lid_mask = 0xffff;
 		} else if (kvm_apic_sw_enabled(apic) &&
 				!new->cid_mask /* flat mode */ &&
 				kvm_apic_get_reg(apic, APIC_DFR) == APIC_DFR_CLUSTER) {
```
