# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 142_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `142_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1509-1549 of the vulnerable file.

	INST_DECL (sub,    0xfc00, 0x1800, 1,      2,   SUB    ), // SUB Rd, Rr
	INST_DECL (in,     0xf800, 0xb000, 1,      2,   IO     ), // IN Rd, A
	//INST_DECL (lds16,  0xf800, 0xa000, 1,      2,   LOAD   ), // LDS Rd, k
	INST_DECL (out,    0xf800, 0xb800, 1,      2,   IO     ), // OUT A, Rr
	INST_DECL (andi,   0xf000, 0x7000, 1,      2,   AND    ), // ANDI Rd, K
	INST_DECL (cpi,    0xf000, 0x3000, 1,      2,   CMP    ), // CPI Rd, K
	INST_DECL (ldi,    0xf000, 0xe000, 1,      2,   LOAD   ), // LDI Rd, K
	INST_DECL (ori,    0xf000, 0x6000, 1,      2,   OR     ), // ORI Rd, K
	INST_DECL (rcall,  0xf000, 0xd000, 0,      2,   CALL   ), // RCALL k
	INST_DECL (rjmp,   0xf000, 0xc000, 2,      2,   JMP    ), // RJMP k
	INST_DECL (sbci,   0xf000, 0x4000, 1,      2,   SUB    ), // SBC Rd, Rr
	INST_DECL (subi,   0xf000, 0x5000, 1,      2,   SUB    ), // SUBI Rd, Rr
	INST_DECL (ldd,    0xd200, 0x8000, 0,      2,   LOAD   ), // LD Rd, Y/Z+q
	INST_DECL (std,    0xd200, 0x8200, 0,      2,   STORE  ), // ST Y/Z+q, Rr

	INST_LAST
};

static OPCODE_DESC* avr_op_analyze(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, CPU_MODEL *cpu) {
	OPCODE_DESC *opcode_desc;
	ut16 ins = (buf[1] << 8) | buf[0];
	int fail;
	char *t;

	// initialize op struct
	memset (op, 0, sizeof (RAnalOp));
	op->ptr = UT64_MAX;
	op->val = UT64_MAX;
	op->jump = UT64_MAX;
	r_strbuf_init (&op->esil);

	// process opcode
	for (opcode_desc = opcodes; opcode_desc->handler; opcode_desc++) {
		if ((ins & opcode_desc->mask) == opcode_desc->selector) {
			fail = 0;

			// copy default cycles/size values
			op->cycles = opcode_desc->cycles;
			op->size = opcode_desc->size;
			op->type = opcode_desc->type;
			op->jump = UT64_MAX;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1526,6 +1526,9 @@
 
 static OPCODE_DESC* avr_op_analyze(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, CPU_MODEL *cpu) {
 	OPCODE_DESC *opcode_desc;
+	if (len < 2) {
+		return NULL;
+	}
 	ut16 ins = (buf[1] << 8) | buf[0];
 	int fail;
 	char *t;
```
