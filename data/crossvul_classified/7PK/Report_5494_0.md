# CrossVul Fix Pair: 7PK in c
**Pair ID:** 5494_0
**Vulnerability Class:** 7PK
**CWE:** CWE-388
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5494_0`)

## Vulnerability Information & PoC

## Description
7PK - Errors

## Vulnerable Code
```c
Lines 1372-1412 of the vulnerable file.

static inline bool nested_cpu_has_vpid(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_ENABLE_VPID);
}

static inline bool nested_cpu_has_apic_reg_virt(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_APIC_REGISTER_VIRT);
}

static inline bool nested_cpu_has_vid(struct vmcs12 *vmcs12)
{
	return nested_cpu_has2(vmcs12, SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
}

static inline bool nested_cpu_has_posted_intr(struct vmcs12 *vmcs12)
{
	return vmcs12->pin_based_vm_exec_control & PIN_BASED_POSTED_INTR;
}

static inline bool is_exception(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_HARD_EXCEPTION | INTR_INFO_VALID_MASK);
}

static void nested_vmx_vmexit(struct kvm_vcpu *vcpu, u32 exit_reason,
			      u32 exit_intr_info,
			      unsigned long exit_qualification);
static void nested_vmx_entry_failure(struct kvm_vcpu *vcpu,
			struct vmcs12 *vmcs12,
			u32 reason, unsigned long qualification);

static int __find_msr_index(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; ++i)
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return i;
	return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1389,10 +1389,10 @@
 	return vmcs12->pin_based_vm_exec_control & PIN_BASED_POSTED_INTR;
 }
 
-static inline bool is_exception(u32 intr_info)
+static inline bool is_nmi(u32 intr_info)
 {
 	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
-		== (INTR_TYPE_HARD_EXCEPTION | INTR_INFO_VALID_MASK);
+		== (INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK);
 }
 
 static void nested_vmx_vmexit(struct kvm_vcpu *vcpu, u32 exit_reason,
@@ -5728,7 +5728,7 @@
 	if (is_machine_check(intr_info))
 		return handle_machine_check(vcpu);
 
-	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
+	if (is_nmi(intr_info))
 		return 1;  /* already handled by vmx_vcpu_run() */
 
 	if (is_no_device(intr_info)) {
@@ -8170,7 +8170,7 @@
 
 	switch (exit_reason) {
 	case EXIT_REASON_EXCEPTION_NMI:
-		if (!is_exception(intr_info))
+		if (is_nmi(intr_info))
 			return false;
 		else if (is_page_fault(intr_info))
 			return enable_ept;
@@ -8765,8 +8765,7 @@
 		kvm_machine_check();
 
 	/* We need to handle NMIs before interrupts are enabled */
-	if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
-	    (exit_intr_info & INTR_INFO_VALID_MASK)) {
+	if (is_nmi(exit_intr_info)) {
 		kvm_before_handle_nmi(&vmx->vcpu);
 		asm("int $2");
 		kvm_after_handle_nmi(&vmx->vcpu);
```
