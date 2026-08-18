# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 503_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `503_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 720-760 of the vulnerable file.


static bool parseOperands(char* str, ArmOp *op) {
	char *t = strdup (str);
	int operand = 0;
	char *token = t;
	char *x;
	int imm_count = 0;
	int mem_opt = 0;
	if (!token) {
		return false;
	}

	while (token) {
		char *next = strchr (token, ',');
		if (next) {
			*next++ = 0;
		}
		while (token[0] == ' ') {
			token++;
		}
		op->operands[operand].type = ARM_NOTYPE;
		op->operands[operand].reg_type = ARM_UNDEFINED;
		op->operands[operand].shift = ARM_NO_SHIFT;

		while (token[0] == ' ' || token[0] == '[' || token[0] == ']') {
			token ++;
		}

		if (!strncmp (token, "lsl", 3)) {
			op->operands[operand].shift = ARM_LSL;
		} else if (!strncmp (token, "lsr", 3)) {
			op->operands[operand].shift = ARM_LSR;
		} else if (!strncmp (token, "asr", 3)) {
			op->operands[operand].shift = ARM_ASR;
		}
		if (op->operands[operand].shift != ARM_NO_SHIFT) {
			op->operands_count ++;
			op->operands[operand].shift_amount = r_num_math (NULL, token + 4);
			if (op->operands[operand].shift_amount > 63) {
				return false;
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -737,6 +737,10 @@
 		while (token[0] == ' ') {
 			token++;
 		}
+		if (operand >= MAX_OPERANDS) {
+			eprintf ("Too many operands\n");
+			return false;
+		}
 		op->operands[operand].type = ARM_NOTYPE;
 		op->operands[operand].reg_type = ARM_UNDEFINED;
 		op->operands[operand].shift = ARM_NO_SHIFT;
```
