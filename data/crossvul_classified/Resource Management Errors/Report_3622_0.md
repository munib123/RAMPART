# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3622_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3622_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1152-1192 of the vulnerable file.

	struct kvm_vcpu *vcpu;
	wait_queue_head_t *q;

	vcpu  = container_of(data, struct kvm_vcpu, arch.hlt_timer);
	q = &vcpu->wq;

	if (vcpu->arch.mp_state != KVM_MP_STATE_HALTED)
		goto out;

	if (waitqueue_active(q))
		wake_up_interruptible(q);

out:
	vcpu->arch.timer_fired = 1;
	vcpu->arch.timer_check = 1;
	return HRTIMER_NORESTART;
}

#define PALE_RESET_ENTRY    0x80000000ffffffb0UL

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu *v;
	int r;
	int i;
	long itc_offset;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_pt_regs *regs = vcpu_regs(vcpu);

	union context *p_ctx = &vcpu->arch.guest;
	struct kvm_vcpu *vmm_vcpu = to_guest(vcpu->kvm, vcpu);

	/*Init vcpu context for first run.*/
	if (IS_ERR(vmm_vcpu))
		return PTR_ERR(vmm_vcpu);

	if (kvm_vcpu_is_bsp(vcpu)) {
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

		/*Set entry address for first run.*/
		regs->cr_iip = PALE_RESET_ENTRY;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1169,6 +1169,11 @@
 
 #define PALE_RESET_ENTRY    0x80000000ffffffb0UL
 
+bool kvm_vcpu_compatible(struct kvm_vcpu *vcpu)
+{
+	return irqchip_in_kernel(vcpu->kcm) == (vcpu->arch.apic != NULL);
+}
+
 int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
 {
 	struct kvm_vcpu *v;
```
