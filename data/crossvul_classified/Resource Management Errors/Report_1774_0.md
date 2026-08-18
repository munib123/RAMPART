# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1774_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1774_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1003-1043 of the vulnerable file.

	struct vmcb_control_area *control = &svm->vmcb->control;
	struct vmcb_save_area *save = &svm->vmcb->save;

	svm->vcpu.fpu_active = 1;
	svm->vcpu.arch.hflags = 0;

	set_cr_intercept(svm, INTERCEPT_CR0_READ);
	set_cr_intercept(svm, INTERCEPT_CR3_READ);
	set_cr_intercept(svm, INTERCEPT_CR4_READ);
	set_cr_intercept(svm, INTERCEPT_CR0_WRITE);
	set_cr_intercept(svm, INTERCEPT_CR3_WRITE);
	set_cr_intercept(svm, INTERCEPT_CR4_WRITE);
	set_cr_intercept(svm, INTERCEPT_CR8_WRITE);

	set_dr_intercepts(svm);

	set_exception_intercept(svm, PF_VECTOR);
	set_exception_intercept(svm, UD_VECTOR);
	set_exception_intercept(svm, MC_VECTOR);
	set_exception_intercept(svm, AC_VECTOR);

	set_intercept(svm, INTERCEPT_INTR);
	set_intercept(svm, INTERCEPT_NMI);
	set_intercept(svm, INTERCEPT_SMI);
	set_intercept(svm, INTERCEPT_SELECTIVE_CR0);
	set_intercept(svm, INTERCEPT_RDPMC);
	set_intercept(svm, INTERCEPT_CPUID);
	set_intercept(svm, INTERCEPT_INVD);
	set_intercept(svm, INTERCEPT_HLT);
	set_intercept(svm, INTERCEPT_INVLPG);
	set_intercept(svm, INTERCEPT_INVLPGA);
	set_intercept(svm, INTERCEPT_IOIO_PROT);
	set_intercept(svm, INTERCEPT_MSR_PROT);
	set_intercept(svm, INTERCEPT_TASK_SWITCH);
	set_intercept(svm, INTERCEPT_SHUTDOWN);
	set_intercept(svm, INTERCEPT_VMRUN);
	set_intercept(svm, INTERCEPT_VMMCALL);
	set_intercept(svm, INTERCEPT_VMLOAD);
	set_intercept(svm, INTERCEPT_VMSAVE);
	set_intercept(svm, INTERCEPT_STGI);
	set_intercept(svm, INTERCEPT_CLGI);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1020,6 +1020,7 @@
 	set_exception_intercept(svm, UD_VECTOR);
 	set_exception_intercept(svm, MC_VECTOR);
 	set_exception_intercept(svm, AC_VECTOR);
+	set_exception_intercept(svm, DB_VECTOR);
 
 	set_intercept(svm, INTERCEPT_INTR);
 	set_intercept(svm, INTERCEPT_NMI);
@@ -1554,20 +1555,13 @@
 	mark_dirty(svm->vmcb, VMCB_SEG);
 }
 
-static void update_db_bp_intercept(struct kvm_vcpu *vcpu)
-{
-	struct vcpu_svm *svm = to_svm(vcpu);
-
-	clr_exception_intercept(svm, DB_VECTOR);
+static void update_bp_intercept(struct kvm_vcpu *vcpu)
+{
+	struct vcpu_svm *svm = to_svm(vcpu);
+
 	clr_exception_intercept(svm, BP_VECTOR);
 
-	if (svm->nmi_singlestep)
-		set_exception_intercept(svm, DB_VECTOR);
-
 	if (vcpu->guest_debug & KVM_GUESTDBG_ENABLE) {
-		if (vcpu->guest_debug &
-		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
-			set_exception_intercept(svm, DB_VECTOR);
 		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
 			set_exception_intercept(svm, BP_VECTOR);
 	} else
@@ -1673,7 +1667,6 @@
 		if (!(svm->vcpu.guest_debug & KVM_GUESTDBG_SINGLESTEP))
 			svm->vmcb->save.rflags &=
 				~(X86_EFLAGS_TF | X86_EFLAGS_RF);
-		update_db_bp_intercept(&svm->vcpu);
 	}
 
 	if (svm->vcpu.guest_debug &
@@ -3661,7 +3654,6 @@
 	 */
 	svm->nmi_singlestep = true;
 	svm->vmcb->save.rflags |= (X86_EFLAGS_TF | X86_EFLAGS_RF);
-	update_db_bp_intercept(vcpu);
 }
 
 static int svm_set_tss_addr(struct kvm *kvm, unsigned int addr)
@@ -4287,7 +4279,7 @@
 	.vcpu_load = svm_vcpu_load,
 	.vcpu_put = svm_vcpu_put,
 
-	.update_db_bp_intercept = update_db_bp_intercept,
+	.update_db_bp_intercept = update_bp_intercept,
 	.get_msr = svm_get_msr,
 	.set_msr = svm_set_msr,
 	.get_segment_base = svm_get_segment_base,
```
