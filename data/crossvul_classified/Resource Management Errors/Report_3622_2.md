# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3622_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3622_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 758-798 of the vulnerable file.

#ifdef CONFIG_HAVE_KVM_IRQCHIP
static inline void kvm_irq_routing_update(struct kvm *kvm,
					  struct kvm_irq_routing_table *irq_rt)
{
	rcu_assign_pointer(kvm->irq_routing, irq_rt);
}
#endif

static inline int kvm_ioeventfd(struct kvm *kvm, struct kvm_ioeventfd *args)
{
	return -ENOSYS;
}

#endif /* CONFIG_HAVE_KVM_EVENTFD */

#ifdef CONFIG_KVM_APIC_ARCHITECTURE
static inline bool kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return vcpu->kvm->bsp_vcpu_id == vcpu->vcpu_id;
}
#endif

#ifdef __KVM_HAVE_DEVICE_ASSIGNMENT

long kvm_vm_ioctl_assigned_device(struct kvm *kvm, unsigned ioctl,
				  unsigned long arg);

#else

static inline long kvm_vm_ioctl_assigned_device(struct kvm *kvm, unsigned ioctl,
						unsigned long arg)
{
	return -ENOTTY;
}

#endif

static inline void kvm_make_request(int req, struct kvm_vcpu *vcpu)
{
	set_bit(req, &vcpu->requests);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -775,6 +775,13 @@
 {
 	return vcpu->kvm->bsp_vcpu_id == vcpu->vcpu_id;
 }
+
+bool kvm_vcpu_compatible(struct kvm_vcpu *vcpu);
+
+#else
+
+static inline bool kvm_vcpu_compatible(struct kvm_vcpu *vcpu) { return true; }
+
 #endif
 
 #ifdef __KVM_HAVE_DEVICE_ASSIGNMENT
```
