# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3622_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3622_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 3114-3154 of the vulnerable file.

		r = kvm_vm_ioctl_set_identity_map_addr(kvm, ident_addr);
		if (r < 0)
			goto out;
		break;
	}
	case KVM_SET_NR_MMU_PAGES:
		r = kvm_vm_ioctl_set_nr_mmu_pages(kvm, arg);
		if (r)
			goto out;
		break;
	case KVM_GET_NR_MMU_PAGES:
		r = kvm_vm_ioctl_get_nr_mmu_pages(kvm);
		break;
	case KVM_CREATE_IRQCHIP: {
		struct kvm_pic *vpic;

		mutex_lock(&kvm->lock);
		r = -EEXIST;
		if (kvm->arch.vpic)
			goto create_irqchip_unlock;
		r = -ENOMEM;
		vpic = kvm_create_pic(kvm);
		if (vpic) {
			r = kvm_ioapic_init(kvm);
			if (r) {
				mutex_lock(&kvm->slots_lock);
				kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS,
							  &vpic->dev_master);
				kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS,
							  &vpic->dev_slave);
				kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS,
							  &vpic->dev_eclr);
				mutex_unlock(&kvm->slots_lock);
				kfree(vpic);
				goto create_irqchip_unlock;
			}
		} else
			goto create_irqchip_unlock;
		smp_wmb();
		kvm->arch.vpic = vpic;
		smp_wmb();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3131,6 +3131,9 @@
 		r = -EEXIST;
 		if (kvm->arch.vpic)
 			goto create_irqchip_unlock;
+		r = -EINVAL;
+		if (atomic_read(&kvm->online_vcpus))
+			goto create_irqchip_unlock;
 		r = -ENOMEM;
 		vpic = kvm_create_pic(kvm);
 		if (vpic) {
@@ -5956,6 +5959,11 @@
 	kvm_x86_ops->check_processor_compatibility(rtn);
 }
 
+bool kvm_vcpu_compatible(struct kvm_vcpu *vcpu)
+{
+	return irqchip_in_kernel(vcpu->kvm) == (vcpu->arch.apic != NULL);
+}
+
 int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
 {
 	struct page *page;
```
