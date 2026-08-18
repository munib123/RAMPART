# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 149_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `149_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 746-786 of the vulnerable file.

	movl_rdisp_reg,
	first_nibble_is_6,
	add_imm,
	first_nibble_is_8,
	movw_pcdisp_reg,
	bra,
	bsr,
	first_nibble_is_c,
	movl_pcdisp_reg,
	mov_imm_reg,
	fpu_insn
};


/* This is the basic operation analysis. Just initialize and jump to
 * routines defined in first_nibble_decode table
 */
static int sh_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	ut8 op_MSB,op_LSB;
	int ret;
	if (!data)
		return 0;
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;

	op->size = 2;

	op_MSB = anal->big_endian? data[0]: data[1];
	op_LSB = anal->big_endian? data[1]: data[0];
	ret =  first_nibble_decode[(op_MSB>>4) & 0x0F](anal, op, (ut16)(op_MSB<<8 | op_LSB));
	return ret;
}

/* Set the profile register */
static int sh_set_reg_profile(RAnal* anal){
	//TODO Add system ( ssr, spc ) + fpu regs
	const char *p =
		"=PC    pc\n"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -763,8 +763,9 @@
 static int sh_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
 	ut8 op_MSB,op_LSB;
 	int ret;
-	if (!data)
+	if (!data || len < 2) {
 		return 0;
+	}
 	memset (op, '\0', sizeof (RAnalOp));
 	op->addr = addr;
 	op->type = R_ANAL_OP_TYPE_UNK;
```
