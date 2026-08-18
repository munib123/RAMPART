# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 141_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `141_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1270-1310 of the vulnerable file.

	int d = ((buf[0] & 0x30) >> 3) + 24;
	int k = (buf[0] & 0xf) | ((buf[0] >> 2) & 0x30);
	op->val = k;
	ESIL_A ("%d,r%d:r%d,-,", k, d + 1, d);		// 0(Rd+1:Rd - Rr)
	ESIL_A ("r%d,0x80,&,!,!,"			// V
		"0,RPICK,0x8000,&,!,"
		"&,vf,=,", d + 1);
	ESIL_A ("0,RPICK,0x8000,&,!,!,nf,=,");		// N
	ESIL_A ("0,RPICK,!,zf,=,");			// Z
	ESIL_A ("r%d,0x80,&,!,"				// C
		"0,RPICK,0x8000,&,!,!,"
		"&,cf,=,", d + 1);
	ESIL_A ("vf,nf,^,sf,=,");			// S
	ESIL_A ("r%d:r%d,=,", d + 1, d);		// Rd = result
}

INST_HANDLER (sbrx) {	// SBRC Rr, b
			// SBRS Rr, b
	int b = buf[0] & 0x7;
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x01) << 4);
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
			// In case of evaluating to false, this instruction
			// needs 2/3 cycles, elsewhere it needs only 1 cycle.
	ESIL_A ("%d,1,<<,r%d,&,", b, r);			// Rr(b)
	ESIL_A ((buf[1] & 0xe) == 0xc
			? "!,"		// SBRC => branch if cleared
			: "!,!,");	// SBRS => branch if set
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1287,7 +1287,7 @@
 			// SBRS Rr, b
 	int b = buf[0] & 0x7;
 	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x01) << 4);
-	RAnalOp next_op;
+	RAnalOp next_op = {0};
 
 	// calculate next instruction size (call recursively avr_op_analyze)
 	// and free next_op's esil string (we dont need it now)
```
