# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2319_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2319_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.

#include <linux/list.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/stat.h>
#include <linux/dmar.h>
#include <linux/iommu.h>
#include <linux/intel-iommu.h>

static bool allow_unsafe_assigned_interrupts;
module_param_named(allow_unsafe_assigned_interrupts,
		   allow_unsafe_assigned_interrupts, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(allow_unsafe_assigned_interrupts,
 "Enable device assignment on platforms without interrupt remapping support.");

static int kvm_iommu_unmap_memslots(struct kvm *kvm);
static void kvm_iommu_put_pages(struct kvm *kvm,
				gfn_t base_gfn, unsigned long npages);

static pfn_t kvm_pin_pages(struct kvm_memory_slot *slot, gfn_t gfn,
			   unsigned long size)
{
	gfn_t end_gfn;
	pfn_t pfn;

	pfn     = gfn_to_pfn_memslot(slot, gfn);
	end_gfn = gfn + (size >> PAGE_SHIFT);
	gfn    += 1;

	if (is_error_noslot_pfn(pfn))
		return pfn;

	while (gfn < end_gfn)
		gfn_to_pfn_memslot(slot, gfn++);

	return pfn;
}

static void kvm_unpin_pages(struct kvm *kvm, pfn_t pfn, unsigned long npages)
{
	unsigned long i;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,13 +43,13 @@
 				gfn_t base_gfn, unsigned long npages);
 
 static pfn_t kvm_pin_pages(struct kvm_memory_slot *slot, gfn_t gfn,
-			   unsigned long size)
+			   unsigned long npages)
 {
 	gfn_t end_gfn;
 	pfn_t pfn;
 
 	pfn     = gfn_to_pfn_memslot(slot, gfn);
-	end_gfn = gfn + (size >> PAGE_SHIFT);
+	end_gfn = gfn + npages;
 	gfn    += 1;
 
 	if (is_error_noslot_pfn(pfn))
@@ -119,7 +119,7 @@
 		 * Pin all pages we are about to map in memory. This is
 		 * important because we unmap and unpin in 4kb steps later.
 		 */
-		pfn = kvm_pin_pages(slot, gfn, page_size);
+		pfn = kvm_pin_pages(slot, gfn, page_size >> PAGE_SHIFT);
 		if (is_error_noslot_pfn(pfn)) {
 			gfn += 1;
 			continue;
@@ -131,7 +131,7 @@
 		if (r) {
 			printk(KERN_ERR "kvm_iommu_map_address:"
 			       "iommu failed to map pfn=%llx\n", pfn);
-			kvm_unpin_pages(kvm, pfn, page_size);
+			kvm_unpin_pages(kvm, pfn, page_size >> PAGE_SHIFT);
 			goto unmap_pages;
 		}
 
```
