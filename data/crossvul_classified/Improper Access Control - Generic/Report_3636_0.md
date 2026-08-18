# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3636_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3636_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 576-616 of the vulnerable file.

void kvm_get_intr_delivery_bitmask(struct kvm_ioapic *ioapic,
				   union kvm_ioapic_redirect_entry *entry,
				   unsigned long *deliver_bitmask);
#endif
int kvm_set_irq(struct kvm *kvm, int irq_source_id, u32 irq, int level);
int kvm_set_msi(struct kvm_kernel_irq_routing_entry *irq_entry, struct kvm *kvm,
		int irq_source_id, int level);
void kvm_notify_acked_irq(struct kvm *kvm, unsigned irqchip, unsigned pin);
void kvm_register_irq_ack_notifier(struct kvm *kvm,
				   struct kvm_irq_ack_notifier *kian);
void kvm_unregister_irq_ack_notifier(struct kvm *kvm,
				   struct kvm_irq_ack_notifier *kian);
int kvm_request_irq_source_id(struct kvm *kvm);
void kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id);

/* For vcpu->arch.iommu_flags */
#define KVM_IOMMU_CACHE_COHERENCY	0x1

#ifdef CONFIG_IOMMU_API
int kvm_iommu_map_pages(struct kvm *kvm, struct kvm_memory_slot *slot);
int kvm_iommu_map_guest(struct kvm *kvm);
int kvm_iommu_unmap_guest(struct kvm *kvm);
int kvm_assign_device(struct kvm *kvm,
		      struct kvm_assigned_dev_kernel *assigned_dev);
int kvm_deassign_device(struct kvm *kvm,
			struct kvm_assigned_dev_kernel *assigned_dev);
#else /* CONFIG_IOMMU_API */
static inline int kvm_iommu_map_pages(struct kvm *kvm,
				      struct kvm_memory_slot *slot)
{
	return 0;
}

static inline int kvm_iommu_map_guest(struct kvm *kvm)
{
	return -ENODEV;
}

static inline int kvm_iommu_unmap_guest(struct kvm *kvm)
{
	return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -593,6 +593,7 @@
 
 #ifdef CONFIG_IOMMU_API
 int kvm_iommu_map_pages(struct kvm *kvm, struct kvm_memory_slot *slot);
+void kvm_iommu_unmap_pages(struct kvm *kvm, struct kvm_memory_slot *slot);
 int kvm_iommu_map_guest(struct kvm *kvm);
 int kvm_iommu_unmap_guest(struct kvm *kvm);
 int kvm_assign_device(struct kvm *kvm,
@@ -604,6 +605,11 @@
 				      struct kvm_memory_slot *slot)
 {
 	return 0;
+}
+
+static inline void kvm_iommu_unmap_pages(struct kvm *kvm,
+					 struct kvm_memory_slot *slot)
+{
 }
 
 static inline int kvm_iommu_map_guest(struct kvm *kvm)
```
