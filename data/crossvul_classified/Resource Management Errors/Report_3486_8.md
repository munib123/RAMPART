# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3486_8
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3486_8`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 561-601 of the vulnerable file.


	if (put_user(regs->regs[reg], vaddr))
		return SIGSEGV;

	regs->regs[reg] = 1;

	return 0;
}

/*
 * ll uses the opcode of lwc0 and sc uses the opcode of swc0.  That is both
 * opcodes are supposed to result in coprocessor unusable exceptions if
 * executed on ll/sc-less processors.  That's the theory.  In practice a
 * few processors such as NEC's VR4100 throw reserved instruction exceptions
 * instead, so we're doing the emulation thing in both exception handlers.
 */
static int simulate_llsc(struct pt_regs *regs, unsigned int opcode)
{
	if ((opcode & OPCODE) == LL) {
		perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS,
				1, 0, regs, 0);
		return simulate_ll(regs, opcode);
	}
	if ((opcode & OPCODE) == SC) {
		perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS,
				1, 0, regs, 0);
		return simulate_sc(regs, opcode);
	}

	return -1;			/* Must be something else ... */
}

/*
 * Simulate trapping 'rdhwr' instructions to provide user accessible
 * registers not implemented in hardware.
 */
static int simulate_rdhwr(struct pt_regs *regs, unsigned int opcode)
{
	struct thread_info *ti = task_thread_info(current);

	if ((opcode & OPCODE) == SPEC3 && (opcode & FUNC) == RDHWR) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -578,12 +578,12 @@
 {
 	if ((opcode & OPCODE) == LL) {
 		perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS,
-				1, 0, regs, 0);
+				1, regs, 0);
 		return simulate_ll(regs, opcode);
 	}
 	if ((opcode & OPCODE) == SC) {
 		perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS,
-				1, 0, regs, 0);
+				1, regs, 0);
 		return simulate_sc(regs, opcode);
 	}
 
@@ -602,7 +602,7 @@
 		int rd = (opcode & RD) >> 11;
 		int rt = (opcode & RT) >> 16;
 		perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS,
-				1, 0, regs, 0);
+				1, regs, 0);
 		switch (rd) {
 		case 0:		/* CPU number */
 			regs->regs[rt] = smp_processor_id();
@@ -640,7 +640,7 @@
 {
 	if ((opcode & OPCODE) == SPEC0 && (opcode & FUNC) == SYNC) {
 		perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS,
-				1, 0, regs, 0);
+				1, regs, 0);
 		return 0;
 	}
 
```
