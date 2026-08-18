# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 500_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `500_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 4558-4599 of the vulnerable file.

		// address := part {+ part}*
		op->offset = op->scale[0] = op->scale[1] = 0;

		ut64 temp = 1;
		Register reg = X86R_UNDEFINED;
		bool first_reg = true;
		while (str[pos] != ']') {
			if (pos > nextpos) {
			//	eprintf ("Error parsing instruction\n");
				break;
			}
			pos = nextpos;
			if (!str[pos]) {
				break;
			}
			last_type = getToken (str, &pos, &nextpos);

			if (last_type == TT_SPECIAL) {
				if (str[pos] == '+' || str[pos] == '-' || str[pos] == ']') {
					if (reg != X86R_UNDEFINED) {
						op->regs[reg_index] = reg;
						op->scale[reg_index] = temp;
						++reg_index;
					} else {
						op->offset += temp;
						op->regs[reg_index] = X86R_UNDEFINED;
					}

					temp = 1;
					reg = X86R_UNDEFINED;
				} else if (str[pos] == '*') {
					// go to ], + or - to get scale

					// Something to do here?
					// Seems we are just ignoring '*' or assuming it implicitly.
				}
			}
			else if (last_type == TT_WORD) {
				ut32 reg_type = 0;

				// We can't multiply registers
				if (reg != X86R_UNDEFINED) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4575,14 +4575,17 @@
 			if (last_type == TT_SPECIAL) {
 				if (str[pos] == '+' || str[pos] == '-' || str[pos] == ']') {
 					if (reg != X86R_UNDEFINED) {
-						op->regs[reg_index] = reg;
-						op->scale[reg_index] = temp;
+						if (reg_index < 2) {
+							op->regs[reg_index] = reg;
+							op->scale[reg_index] = temp;
+						}
 						++reg_index;
 					} else {
 						op->offset += temp;
-						op->regs[reg_index] = X86R_UNDEFINED;
+						if (reg_index < 2) {
+							op->regs[reg_index] = X86R_UNDEFINED;
+						}
 					}
-
 					temp = 1;
 					reg = X86R_UNDEFINED;
 				} else if (str[pos] == '*') {
```
