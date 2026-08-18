# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5785_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5785_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 475-515 of the vulnerable file.


	/*
	 * Handle the "start in power-off" case by calling into the
	 * PSCI code.
	 */
	if (test_and_clear_bit(KVM_ARM_VCPU_POWER_OFF, vcpu->arch.features)) {
		*vcpu_reg(vcpu, 0) = KVM_PSCI_FN_CPU_OFF;
		kvm_psci_call(vcpu);
	}

	return 0;
}

static void vcpu_pause(struct kvm_vcpu *vcpu)
{
	wait_queue_head_t *wq = kvm_arch_vcpu_wq(vcpu);

	wait_event_interruptible(*wq, !vcpu->arch.pause);
}

/**
 * kvm_arch_vcpu_ioctl_run - the main VCPU run function to execute guest code
 * @vcpu:	The VCPU pointer
 * @run:	The kvm_run structure pointer used for userspace state exchange
 *
 * This function is called through the VCPU_RUN ioctl called from user space. It
 * will execute VM code in a loop until the time slice for the process is used
 * or some emulation is needed from user space in which case the function will
 * return with return value 0 and with the kvm_run structure filled in with the
 * required data for the requested emulation.
 */
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret;
	sigset_t sigsaved;

	/* Make sure they initialize the vcpu with KVM_ARM_VCPU_INIT */
	if (unlikely(vcpu->arch.target < 0))
		return -ENOEXEC;

	ret = kvm_vcpu_first_run_init(vcpu);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -492,6 +492,11 @@
 	wait_event_interruptible(*wq, !vcpu->arch.pause);
 }
 
+static int kvm_vcpu_initialized(struct kvm_vcpu *vcpu)
+{
+	return vcpu->arch.target >= 0;
+}
+
 /**
  * kvm_arch_vcpu_ioctl_run - the main VCPU run function to execute guest code
  * @vcpu:	The VCPU pointer
@@ -508,8 +513,7 @@
 	int ret;
 	sigset_t sigsaved;
 
-	/* Make sure they initialize the vcpu with KVM_ARM_VCPU_INIT */
-	if (unlikely(vcpu->arch.target < 0))
+	if (unlikely(!kvm_vcpu_initialized(vcpu)))
 		return -ENOEXEC;
 
 	ret = kvm_vcpu_first_run_init(vcpu);
@@ -710,6 +714,10 @@
 	case KVM_SET_ONE_REG:
 	case KVM_GET_ONE_REG: {
 		struct kvm_one_reg reg;
+
+		if (unlikely(!kvm_vcpu_initialized(vcpu)))
+			return -ENOEXEC;
+
 		if (copy_from_user(&reg, argp, sizeof(reg)))
 			return -EFAULT;
 		if (ioctl == KVM_SET_ONE_REG)
@@ -721,6 +729,9 @@
 		struct kvm_reg_list __user *user_list = argp;
 		struct kvm_reg_list reg_list;
 		unsigned n;
+
+		if (unlikely(!kvm_vcpu_initialized(vcpu)))
+			return -ENOEXEC;
 
 		if (copy_from_user(&reg_list, user_list, sizeof(reg_list)))
 			return -EFAULT;
```
