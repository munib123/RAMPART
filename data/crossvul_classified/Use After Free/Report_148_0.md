# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 148_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `148_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 602-642 of the vulnerable file.

}

INST_HANDLER (cpc) {	// CPC Rd, Rr
	int r = (buf[0]        & 0x0f) | ((buf[1] << 3) & 0x10);
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);

	ESIL_A ("cf,r%d,+,r%d,-,", r, d);		// Rd - Rr - C
	__generic_sub_update_flags_rr (op, d, r, 1);	// FLAGS (carry)
}

INST_HANDLER (cpi) { // CPI Rd, K
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[0] & 0xf) | ((buf[1] & 0xf) << 4);
	ESIL_A ("%d,r%d,-,", k, d);			// Rd - k
	__generic_sub_update_flags_rk (op, d, k, 0);	// FLAGS (carry)
}

INST_HANDLER (cpse) {	// CPSE Rd, Rr
	int r = (buf[0] & 0xf) | ((buf[1] & 0x2) << 3);
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	RAnalOp next_op;

	// calculate next instruction size (call recursively avr_op_analyze)
	// and free next_op's esil string (we dont need it now)
	avr_op_analyze (anal,
			&next_op,
			op->addr + op->size, buf + op->size, len - op->size,
			cpu);
	r_strbuf_fini (&next_op.esil);
	op->jump = op->addr + next_op.size + 2;

	// cycles
	op->cycles = 1;	// XXX: This is a bug, because depends on eval state,
			// so it cannot be really be known until this
			// instruction is executed by the ESIL interpreter!!!
			// In case of evaluating to true, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.
	ESIL_A ("r%d,r%d,^,!,", r, d);			// Rr == Rd
	ESIL_A ("?{,%"PFMT64d",pc,=,},", op->jump);	// ?true => jmp
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -619,7 +619,7 @@
 INST_HANDLER (cpse) {	// CPSE Rd, Rr
 	int r = (buf[0] & 0xf) | ((buf[1] & 0x2) << 3);
 	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
-	RAnalOp next_op;
+	RAnalOp next_op = {0};
 
 	// calculate next instruction size (call recursively avr_op_analyze)
 	// and free next_op's esil string (we dont need it now)
```
