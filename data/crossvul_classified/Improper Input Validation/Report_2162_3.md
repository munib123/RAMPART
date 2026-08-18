# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2162_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2162_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 695-735 of the vulnerable file.


static struct page *nested_get_page(struct kvm_vcpu *vcpu, gpa_t addr)
{
	struct page *page = gfn_to_page(vcpu->kvm, addr >> PAGE_SHIFT);
	if (is_error_page(page))
		return NULL;

	return page;
}

static void nested_release_page(struct page *page)
{
	kvm_release_page_dirty(page);
}

static void nested_release_page_clean(struct page *page)
{
	kvm_release_page_clean(page);
}

static u64 construct_eptp(unsigned long root_hpa);
static void kvm_cpu_vmxon(u64 addr);
static void kvm_cpu_vmxoff(void);
static void vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3);
static int vmx_set_tss_addr(struct kvm *kvm, unsigned int addr);
static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static bool guest_state_valid(struct kvm_vcpu *vcpu);
static u32 vmx_segment_access_rights(struct kvm_segment *var);
static void vmx_sync_pir_to_irr_dummy(struct kvm_vcpu *vcpu);
static void copy_vmcs12_to_shadow(struct vcpu_vmx *vmx);
static void copy_shadow_to_vmcs12(struct vcpu_vmx *vmx);

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
static DEFINE_PER_CPU(struct vmcs *, current_vmcs);
/*
 * We maintain a per-CPU linked-list of VMCS loaded on that CPU. This is needed
 * when a CPU is brought down, and we need to VMCLEAR all VMCSs loaded on it.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -712,6 +712,7 @@
 	kvm_release_page_clean(page);
 }
 
+static unsigned long nested_ept_get_cr3(struct kvm_vcpu *vcpu);
 static u64 construct_eptp(unsigned long root_hpa);
 static void kvm_cpu_vmxon(u64 addr);
 static void kvm_cpu_vmxoff(void);
@@ -2161,6 +2162,7 @@
 static u32 nested_vmx_exit_ctls_low, nested_vmx_exit_ctls_high;
 static u32 nested_vmx_entry_ctls_low, nested_vmx_entry_ctls_high;
 static u32 nested_vmx_misc_low, nested_vmx_misc_high;
+static u32 nested_vmx_ept_caps;
 static __init void nested_vmx_setup_ctls_msrs(void)
 {
 	/*
@@ -6279,6 +6281,74 @@
 	return 1;
 }
 
+/* Emulate the INVEPT instruction */
+static int handle_invept(struct kvm_vcpu *vcpu)
+{
+	u32 vmx_instruction_info, types;
+	unsigned long type;
+	gva_t gva;
+	struct x86_exception e;
+	struct {
+		u64 eptp, gpa;
+	} operand;
+	u64 eptp_mask = ((1ull << 51) - 1) & PAGE_MASK;
+
+	if (!(nested_vmx_secondary_ctls_high & SECONDARY_EXEC_ENABLE_EPT) ||
+	    !(nested_vmx_ept_caps & VMX_EPT_INVEPT_BIT)) {
+		kvm_queue_exception(vcpu, UD_VECTOR);
+		return 1;
+	}
+
+	if (!nested_vmx_check_permission(vcpu))
+		return 1;
+
+	if (!kvm_read_cr0_bits(vcpu, X86_CR0_PE)) {
+		kvm_queue_exception(vcpu, UD_VECTOR);
+		return 1;
+	}
+
+	vmx_instruction_info = vmcs_read32(VMX_INSTRUCTION_INFO);
+	type = kvm_register_read(vcpu, (vmx_instruction_info >> 28) & 0xf);
+
+	types = (nested_vmx_ept_caps >> VMX_EPT_EXTENT_SHIFT) & 6;
+
+	if (!(types & (1UL << type))) {
+		nested_vmx_failValid(vcpu,
+				VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
+		return 1;
+	}
+
+	/* According to the Intel VMX instruction reference, the memory
+	 * operand is read even if it isn't needed (e.g., for type==global)
+	 */
+	if (get_vmx_mem_address(vcpu, vmcs_readl(EXIT_QUALIFICATION),
+			vmx_instruction_info, &gva))
+		return 1;
+	if (kvm_read_guest_virt(&vcpu->arch.emulate_ctxt, gva, &operand,
+				sizeof(operand), &e)) {
+		kvm_inject_page_fault(vcpu, &e);
+		return 1;
+	}
+
+	switch (type) {
+	case VMX_EPT_EXTENT_CONTEXT:
+		if ((operand.eptp & eptp_mask) !=
+				(nested_ept_get_cr3(vcpu) & eptp_mask))
+			break;
+	case VMX_EPT_EXTENT_GLOBAL:
+		kvm_mmu_sync_roots(vcpu);
+		kvm_mmu_flush_tlb(vcpu);
+		nested_vmx_succeed(vcpu);
+		break;
+	default:
+		BUG_ON(1);
+		break;
+	}
+
+	skip_emulated_instruction(vcpu);
+	return 1;
+}
+
 /*
  * The exit handlers return 1 if the exit was handled fully and guest execution
  * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
@@ -6323,6 +6393,7 @@
 	[EXIT_REASON_PAUSE_INSTRUCTION]       = handle_pause,
 	[EXIT_REASON_MWAIT_INSTRUCTION]	      = handle_invalid_op,
 	[EXIT_REASON_MONITOR_INSTRUCTION]     = handle_invalid_op,
+	[EXIT_REASON_INVEPT]                  = handle_invept,
 };
 
 static const int kvm_vmx_max_exit_handlers =
@@ -6549,6 +6620,7 @@
 	case EXIT_REASON_VMPTRST: case EXIT_REASON_VMREAD:
 	case EXIT_REASON_VMRESUME: case EXIT_REASON_VMWRITE:
 	case EXIT_REASON_VMOFF: case EXIT_REASON_VMON:
+	case EXIT_REASON_INVEPT:
 		/*
 		 * VMX instructions trap unconditionally. This allows L1 to
 		 * emulate them for its L2 guest, i.e., allows 3-level nesting!
```
