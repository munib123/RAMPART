# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3486_5
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3486_5`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 166-206 of the vulnerable file.


		if (type == TYPE_SWPB)
			swpbcounter++;
		else
			swpcounter++;
	}

	return res;
}

/*
 * swp_handler logs the id of calling process, dissects the instruction, sanity
 * checks the memory location, calls emulate_swpX for the actual operation and
 * deals with fixup/error handling before returning
 */
static int swp_handler(struct pt_regs *regs, unsigned int instr)
{
	unsigned int address, destreg, data, type;
	unsigned int res = 0;

	perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS, 1, 0, regs, regs->ARM_pc);

	if (current->pid != previous_pid) {
		pr_debug("\"%s\" (%ld) uses deprecated SWP{B} instruction\n",
			 current->comm, (unsigned long)current->pid);
		previous_pid = current->pid;
	}

	address = regs->uregs[EXTRACT_REG_NUM(instr, RN_OFFSET)];
	data	= regs->uregs[EXTRACT_REG_NUM(instr, RT2_OFFSET)];
	destreg = EXTRACT_REG_NUM(instr, RT_OFFSET);

	type = instr & TYPE_SWPB;

	pr_debug("addr in r%d->0x%08x, dest is r%d, source in r%d->0x%08x)\n",
		 EXTRACT_REG_NUM(instr, RN_OFFSET), address,
		 destreg, EXTRACT_REG_NUM(instr, RT2_OFFSET), data);

	/* Check access in reasonable access range for both SWP and SWPB */
	if (!access_ok(VERIFY_WRITE, (address & ~3), 4)) {
		pr_debug("SWP{B} emulation: access to %p not allowed!\n",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -183,7 +183,7 @@
 	unsigned int address, destreg, data, type;
 	unsigned int res = 0;
 
-	perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS, 1, 0, regs, regs->ARM_pc);
+	perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS, 1, regs, regs->ARM_pc);
 
 	if (current->pid != previous_pid) {
 		pr_debug("\"%s\" (%ld) uses deprecated SWP{B} instruction\n",
```
