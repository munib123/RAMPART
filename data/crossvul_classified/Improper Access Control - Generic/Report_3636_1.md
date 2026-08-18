# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3636_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3636_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 293-333 of the vulnerable file.


	while (gfn < end_gfn) {
		unsigned long unmap_pages;
		size_t size;

		/* Get physical address */
		phys = iommu_iova_to_phys(domain, gfn_to_gpa(gfn));
		pfn  = phys >> PAGE_SHIFT;

		/* Unmap address from IO address space */
		size       = iommu_unmap(domain, gfn_to_gpa(gfn), PAGE_SIZE);
		unmap_pages = 1ULL << get_order(size);

		/* Unpin all pages we just unmapped to not leak any memory */
		kvm_unpin_pages(kvm, pfn, unmap_pages);

		gfn += unmap_pages;
	}
}

static int kvm_iommu_unmap_memslots(struct kvm *kvm)
{
	int idx;
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;

	idx = srcu_read_lock(&kvm->srcu);
	slots = kvm_memslots(kvm);

	kvm_for_each_memslot(memslot, slots)
		kvm_iommu_put_pages(kvm, memslot->base_gfn, memslot->npages);

	srcu_read_unlock(&kvm->srcu, idx);

	return 0;
}

int kvm_iommu_unmap_guest(struct kvm *kvm)
{
	struct iommu_domain *domain = kvm->arch.iommu_domain;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -310,6 +310,11 @@
 	}
 }
 
+void kvm_iommu_unmap_pages(struct kvm *kvm, struct kvm_memory_slot *slot)
+{
+	kvm_iommu_put_pages(kvm, slot->base_gfn, slot->npages);
+}
+
 static int kvm_iommu_unmap_memslots(struct kvm *kvm)
 {
 	int idx;
@@ -320,7 +325,7 @@
 	slots = kvm_memslots(kvm);
 
 	kvm_for_each_memslot(memslot, slots)
-		kvm_iommu_put_pages(kvm, memslot->base_gfn, memslot->npages);
+		kvm_iommu_unmap_pages(kvm, memslot);
 
 	srcu_read_unlock(&kvm->srcu, idx);
 
```
