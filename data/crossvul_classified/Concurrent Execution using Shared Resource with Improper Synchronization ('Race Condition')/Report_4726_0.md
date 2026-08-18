# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 4726_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4726_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 4297-4337 of the vulnerable file.


	if (ret != X86EMUL_CONTINUE)
		return EMULATE_FAIL;

	vcpu->arch.emulate_ctxt.eip = c->eip;
	memcpy(vcpu->arch.regs, c->regs, sizeof c->regs);
	kvm_rip_write(vcpu, vcpu->arch.emulate_ctxt.eip);
	kvm_x86_ops->set_rflags(vcpu, vcpu->arch.emulate_ctxt.eflags);

	if (irq == NMI_VECTOR)
		vcpu->arch.nmi_pending = false;
	else
		vcpu->arch.interrupt.pending = false;

	return EMULATE_DONE;
}
EXPORT_SYMBOL_GPL(kvm_inject_realmode_interrupt);

static int handle_emulation_failure(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.insn_emulation_fail;
	trace_kvm_emulate_insn_failed(vcpu);
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
	vcpu->run->internal.ndata = 0;
	kvm_queue_exception(vcpu, UD_VECTOR);
	return EMULATE_FAIL;
}

static bool reexecute_instruction(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;

	if (tdp_enabled)
		return false;

	/*
	 * if emulation was due to access to shadowed page table
	 * and it failed try to unshadow page and re-entetr the
	 * guest to let CPU execute the instruction.
	 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4314,13 +4314,19 @@
 
 static int handle_emulation_failure(struct kvm_vcpu *vcpu)
 {
+	int r = EMULATE_DONE;
+
 	++vcpu->stat.insn_emulation_fail;
 	trace_kvm_emulate_insn_failed(vcpu);
-	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
-	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
-	vcpu->run->internal.ndata = 0;
+	if (!is_guest_mode(vcpu)) {
+		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
+		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
+		vcpu->run->internal.ndata = 0;
+		r = EMULATE_FAIL;
+	}
 	kvm_queue_exception(vcpu, UD_VECTOR);
-	return EMULATE_FAIL;
+
+	return r;
 }
 
 static bool reexecute_instruction(struct kvm_vcpu *vcpu, gva_t gva)
```
