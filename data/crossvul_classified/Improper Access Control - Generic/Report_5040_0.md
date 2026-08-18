# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5040_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5040_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 2401-2441 of the vulnerable file.

}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}

static void vmx_set_msr_bitmap(struct kvm_vcpu *vcpu)
{
	unsigned long *msr_bitmap;

	if (is_guest_mode(vcpu))
		msr_bitmap = vmx_msr_bitmap_nested;
	else if (vcpu->arch.apic_base & X2APIC_ENABLE) {
		if (is_long_mode(vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode_x2apic;
		else
			msr_bitmap = vmx_msr_bitmap_legacy_x2apic;
	} else {
		if (is_long_mode(vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode;
		else
			msr_bitmap = vmx_msr_bitmap_legacy;
	}

	vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));
}

/*
 * Set up the vmcs to automatically save and restore system
 * msrs.  Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
static void setup_msrs(struct vcpu_vmx *vmx)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2418,7 +2418,9 @@
 
 	if (is_guest_mode(vcpu))
 		msr_bitmap = vmx_msr_bitmap_nested;
-	else if (vcpu->arch.apic_base & X2APIC_ENABLE) {
+	else if (cpu_has_secondary_exec_ctrls() &&
+		 (vmcs_read32(SECONDARY_VM_EXEC_CONTROL) &
+		  SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE)) {
 		if (is_long_mode(vcpu))
 			msr_bitmap = vmx_msr_bitmap_longmode_x2apic;
 		else
@@ -4783,6 +4785,19 @@
 	struct vcpu_vmx *vmx = to_vmx(vcpu);
 
 	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_ctrl(vmx));
+	if (cpu_has_secondary_exec_ctrls()) {
+		if (kvm_vcpu_apicv_active(vcpu))
+			vmcs_set_bits(SECONDARY_VM_EXEC_CONTROL,
+				      SECONDARY_EXEC_APIC_REGISTER_VIRT |
+				      SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
+		else
+			vmcs_clear_bits(SECONDARY_VM_EXEC_CONTROL,
+					SECONDARY_EXEC_APIC_REGISTER_VIRT |
+					SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
+	}
+
+	if (cpu_has_vmx_msr_bitmap())
+		vmx_set_msr_bitmap(vcpu);
 }
 
 static u32 vmx_exec_control(struct vcpu_vmx *vmx)
@@ -6329,23 +6344,20 @@
 
 	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */
 
-	if (enable_apicv) {
-		for (msr = 0x800; msr <= 0x8ff; msr++)
-			vmx_disable_intercept_msr_read_x2apic(msr);
-
-		/* According SDM, in x2apic mode, the whole id reg is used.
-		 * But in KVM, it only use the highest eight bits. Need to
-		 * intercept it */
-		vmx_enable_intercept_msr_read_x2apic(0x802);
-		/* TMCCT */
-		vmx_enable_intercept_msr_read_x2apic(0x839);
-		/* TPR */
-		vmx_disable_intercept_msr_write_x2apic(0x808);
-		/* EOI */
-		vmx_disable_intercept_msr_write_x2apic(0x80b);
-		/* SELF-IPI */
-		vmx_disable_intercept_msr_write_x2apic(0x83f);
-	}
+	for (msr = 0x800; msr <= 0x8ff; msr++)
+		vmx_disable_intercept_msr_read_x2apic(msr);
+
+	/* According SDM, in x2apic mode, the whole id reg is used.  But in
+	 * KVM, it only use the highest eight bits. Need to intercept it */
+	vmx_enable_intercept_msr_read_x2apic(0x802);
+	/* TMCCT */
+	vmx_enable_intercept_msr_read_x2apic(0x839);
+	/* TPR */
+	vmx_disable_intercept_msr_write_x2apic(0x808);
+	/* EOI */
+	vmx_disable_intercept_msr_write_x2apic(0x80b);
+	/* SELF-IPI */
+	vmx_disable_intercept_msr_write_x2apic(0x83f);
 
 	if (enable_ept) {
 		kvm_mmu_set_mask_ptes(0ull,
```
