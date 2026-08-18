# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2173_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2173_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 455-495 of the vulnerable file.

	 * non-nested (L1) guest, it always points to vmcs01. For a nested
	 * guest (L2), it points to a different VMCS.
	 */
	struct loaded_vmcs    vmcs01;
	struct loaded_vmcs   *loaded_vmcs;
	bool                  __launched; /* temporary, used in vmx_vcpu_run */
	struct msr_autoload {
		unsigned nr;
		struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
		struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
	} msr_autoload;
	struct {
		int           loaded;
		u16           fs_sel, gs_sel, ldt_sel;
#ifdef CONFIG_X86_64
		u16           ds_sel, es_sel;
#endif
		int           gs_ldt_reload_needed;
		int           fs_reload_needed;
		u64           msr_host_bndcfgs;
	} host_state;
	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_segment segs[8];
	} rmode;
	struct {
		u32 bitmask; /* 4 bits per segment (1 bit per field) */
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} seg[8];
	} segment_cache;
	int vpid;
	bool emulation_required;

	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	ktime_t entry_time;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -472,6 +472,7 @@
 		int           gs_ldt_reload_needed;
 		int           fs_reload_needed;
 		u64           msr_host_bndcfgs;
+		unsigned long vmcs_host_cr4;	/* May not match real cr4 */
 	} host_state;
 	struct {
 		int vm86_active;
@@ -4267,10 +4268,15 @@
 	u32 low32, high32;
 	unsigned long tmpl;
 	struct desc_ptr dt;
+	unsigned long cr4;
 
 	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);  /* 22.2.3 */
-	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
 	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3  FIXME: shadow tables */
+
+	/* Save the most likely value for this task's CR4 in the VMCS. */
+	cr4 = read_cr4();
+	vmcs_writel(HOST_CR4, cr4);			/* 22.2.3, 22.2.5 */
+	vmx->host_state.vmcs_host_cr4 = cr4;
 
 	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
 #ifdef CONFIG_X86_64
@@ -7514,7 +7520,7 @@
 static void __noclone vmx_vcpu_run(struct kvm_vcpu *vcpu)
 {
 	struct vcpu_vmx *vmx = to_vmx(vcpu);
-	unsigned long debugctlmsr;
+	unsigned long debugctlmsr, cr4;
 
 	/* Record the guest's net vcpu time for enforced NMI injections. */
 	if (unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked))
@@ -7539,6 +7545,12 @@
 		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
 	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
 		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);
+
+	cr4 = read_cr4();
+	if (unlikely(cr4 != vmx->host_state.vmcs_host_cr4)) {
+		vmcs_writel(HOST_CR4, cr4);
+		vmx->host_state.vmcs_host_cr4 = cr4;
+	}
 
 	/* When single-stepping over STI and MOV SS, we must clear the
 	 * corresponding interruptibility bits in the guest state. Otherwise
```
