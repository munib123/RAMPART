# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5768_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5768_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 774-814 of the vulnerable file.

		new.dirty_bitmap = NULL;

	r = -ENOMEM;

	/* Allocate if a slot is being created */
	if (npages && !old.npages) {
		new.user_alloc = user_alloc;
		new.userspace_addr = mem->userspace_addr;

		if (kvm_arch_create_memslot(&new, npages))
			goto out_free;
	}

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & KVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		if (kvm_create_dirty_bitmap(&new) < 0)
			goto out_free;
		/* destroy any largepage mappings for dirty tracking */
	}

	if (!npages) {
		struct kvm_memory_slot *slot;

		r = -ENOMEM;
		slots = kmemdup(kvm->memslots, sizeof(struct kvm_memslots),
				GFP_KERNEL);
		if (!slots)
			goto out_free;
		slot = id_to_memslot(slots, mem->slot);
		slot->flags |= KVM_MEMSLOT_INVALID;

		update_memslots(slots, NULL);

		old_memslots = kvm->memslots;
		rcu_assign_pointer(kvm->memslots, slots);
		synchronize_srcu_expedited(&kvm->srcu);
		/* From this point no new shadow pages pointing to a deleted
		 * memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 * 	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -791,7 +791,7 @@
 		/* destroy any largepage mappings for dirty tracking */
 	}
 
-	if (!npages) {
+	if (!npages || base_gfn != old.base_gfn) {
 		struct kvm_memory_slot *slot;
 
 		r = -ENOMEM;
@@ -807,8 +807,8 @@
 		old_memslots = kvm->memslots;
 		rcu_assign_pointer(kvm->memslots, slots);
 		synchronize_srcu_expedited(&kvm->srcu);
-		/* From this point no new shadow pages pointing to a deleted
-		 * memslot will be created.
+		/* From this point no new shadow pages pointing to a deleted,
+		 * or moved, memslot will be created.
 		 *
 		 * validation of sp->gfn happens in:
 		 * 	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
```
