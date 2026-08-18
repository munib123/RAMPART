# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 459_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `459_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2006-2046 of the vulnerable file.

				data[l++] = offset >> 48;
				data[l++] = offset >> 54;
			}
			return l;
		}
		if (op->operands[0].type & OT_BYTE && a->bits == 64 && op->operands[1].regs[0]) {
			if (op->operands[1].regs[0] >= X86R_R8 &&
			    op->operands[0].reg < 4) {
				data[l++] = 0x41;
				data[l++] = 0x8a;
				data[l++] = op->operands[0].reg << 3 | (op->operands[1].regs[0] - 8);
				return l;
			}
			return -1;
		}

		if (op->operands[1].type & OT_REGTYPE & OT_SEGMENTREG) {
			if (op->operands[1].scale[0] == 0) {
				return -1;
			}
			data[l++] = SEG_REG_PREFIXES[op->operands[1].regs[0]];
			data[l++] = 0x8b;
			data[l++] = op->operands[0].reg << 3 | 0x5;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
			return l;
		}

		if (a->bits == 64) {
			if (op->operands[0].type & OT_QWORD) {
				if (!(op->operands[1].type & OT_QWORD)) {
					if (op->operands[1].regs[0] != -1) {
						data[l++] = 0x67;
					}
					data[l++] = 0x48;
				}
			} else if (op->operands[1].type & OT_DWORD) {
				data[l++] = 0x44;
			} else if (!(op->operands[1].type & OT_QWORD)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2023,9 +2023,9 @@
 			if (op->operands[1].scale[0] == 0) {
 				return -1;
 			}
-			data[l++] = SEG_REG_PREFIXES[op->operands[1].regs[0]];
+			data[l++] = SEG_REG_PREFIXES[op->operands[1].regs[0] % 6];
 			data[l++] = 0x8b;
-			data[l++] = op->operands[0].reg << 3 | 0x5;
+			data[l++] = (((ut32)op->operands[0].reg) << 3) | 0x5;
 			data[l++] = offset;
 			data[l++] = offset >> 8;
 			data[l++] = offset >> 16;
```
