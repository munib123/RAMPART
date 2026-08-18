# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2524_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2524_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 11817-11857 of the vulnerable file.

	pi_post_block(vcpu);
}

/*
 * vmx_update_pi_irte - set IRTE for Posted-Interrupts
 *
 * @kvm: kvm
 * @host_irq: host irq of the interrupt
 * @guest_irq: gsi of the interrupt
 * @set: set or unset PI
 * returns 0 on success, < 0 on failure
 */
static int vmx_update_pi_irte(struct kvm *kvm, unsigned int host_irq,
			      uint32_t guest_irq, bool set)
{
	struct kvm_kernel_irq_routing_entry *e;
	struct kvm_irq_routing_table *irq_rt;
	struct kvm_lapic_irq irq;
	struct kvm_vcpu *vcpu;
	struct vcpu_data vcpu_info;
	int idx, ret = -EINVAL;

	if (!kvm_arch_has_assigned_device(kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP) ||
		!kvm_vcpu_apicv_active(kvm->vcpus[0]))
		return 0;

	idx = srcu_read_lock(&kvm->irq_srcu);
	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	BUG_ON(guest_irq >= irq_rt->nr_rt_entries);

	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
		if (e->type != KVM_IRQ_ROUTING_MSI)
			continue;
		/*
		 * VT-d PI cannot support posting multicast/broadcast
		 * interrupts to a vCPU, we still use interrupt remapping
		 * for these kind of interrupts.
		 *
		 * For lowest-priority interrupts, we only support
		 * those with single CPU as the destination, e.g. user
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11834,7 +11834,7 @@
 	struct kvm_lapic_irq irq;
 	struct kvm_vcpu *vcpu;
 	struct vcpu_data vcpu_info;
-	int idx, ret = -EINVAL;
+	int idx, ret = 0;
 
 	if (!kvm_arch_has_assigned_device(kvm) ||
 		!irq_remapping_cap(IRQ_POSTING_CAP) ||
@@ -11843,7 +11843,12 @@
 
 	idx = srcu_read_lock(&kvm->irq_srcu);
 	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
-	BUG_ON(guest_irq >= irq_rt->nr_rt_entries);
+	if (guest_irq >= irq_rt->nr_rt_entries ||
+	    hlist_empty(&irq_rt->map[guest_irq])) {
+		pr_warn_once("no route for guest_irq %u/%u (broken user space?)\n",
+			     guest_irq, irq_rt->nr_rt_entries);
+		goto out;
+	}
 
 	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
 		if (e->type != KVM_IRQ_ROUTING_MSI)
```
