# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5613_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5613_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 631-671 of the vulnerable file.

 * Must be called holding mmap_sem for write.
 */
int __kvm_set_memory_region(struct kvm *kvm,
			    struct kvm_userspace_memory_region *mem,
			    int user_alloc)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long i;
	struct kvm_memory_slot *memslot;
	struct kvm_memory_slot old, new;
	struct kvm_memslots *slots, *old_memslots;

	r = -EINVAL;
	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	if (user_alloc && (mem->userspace_addr & (PAGE_SIZE - 1)))
		goto out;
	if (mem->slot >= KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	memslot = &kvm->memslots->memslots[mem->slot];
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages = mem->memory_size >> PAGE_SHIFT;

	r = -EINVAL;
	if (npages > KVM_MEM_MAX_NR_PAGES)
		goto out;

	if (!npages)
		mem->flags &= ~KVM_MEM_LOG_DIRTY_PAGES;

	new = old = *memslot;

	new.id = mem->slot;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -648,7 +648,10 @@
 		goto out;
 	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
 		goto out;
-	if (user_alloc && (mem->userspace_addr & (PAGE_SIZE - 1)))
+	/* We can read the guest memory with __xxx_user() later on. */
+	if (user_alloc &&
+	    ((mem->userspace_addr & (PAGE_SIZE - 1)) ||
+	     !access_ok(VERIFY_WRITE, mem->userspace_addr, mem->memory_size)))
 		goto out;
 	if (mem->slot >= KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)
 		goto out;
@@ -1283,7 +1286,7 @@
 	addr = gfn_to_hva(kvm, gfn);
 	if (kvm_is_error_hva(addr))
 		return -EFAULT;
-	r = copy_from_user(data, (void __user *)addr + offset, len);
+	r = __copy_from_user(data, (void __user *)addr + offset, len);
 	if (r)
 		return -EFAULT;
 	return 0;
```
