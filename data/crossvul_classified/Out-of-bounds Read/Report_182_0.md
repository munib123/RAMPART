# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 182_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `182_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 665-707 of the vulnerable file.

			r_strbuf_setf (&op->esil, "%s,y,==", addrbuf);
		else	r_strbuf_setf (&op->esil, "%s,[1],y,==", addrbuf);
		_6502_anal_update_flags (op, _6502_FLAGS_BNZ);
		// invert C, since C=1 when A-M >= 0
		r_strbuf_append (&op->esil, ",C,!,C,=");
		break;
	// BRANCHES
	case 0x10: // bpl $ffff
	case 0x30: // bmi $ffff
	case 0x50: // bvc $ffff
	case 0x70: // bvs $ffff
	case 0x90: // bcc $ffff
	case 0xb0: // bcs $ffff
	case 0xd0: // bne $ffff
	case 0xf0: // beq $ffff
		// FIXME: Add 1 if branch occurs to same page.
		// FIXME: Add 2 if branch occurs to different page
		op->cycles = 2;
		op->failcycles = 3;
		op->type = R_ANAL_OP_TYPE_CJMP;
		if (data[1] <= 127)
			op->jump = addr + data[1] + op->size;
		else	op->jump = addr - (256 - data[1]) + op->size;
		op->fail = addr + op->size;
		// FIXME: add a type of conditional
		// op->cond = R_ANAL_COND_LE;
		_6502_anal_esil_ccall (op, data[0]);
		break;
	// JSR
	case 0x20: // jsr $ffff
		op->cycles = 6;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = data[1] | data[2] << 8;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 2;
		// JSR pushes the address-1 of the next operation on to the stack before transferring program
		// control to the following address
		// stack is on page one and sp is an 8-bit reg: operations must be done like: sp + 0x100
		r_strbuf_setf (&op->esil, "1,pc,-,0xff,sp,+,=[2],0x%04x,pc,=,2,sp,-=", op->jump);
		break;
	// JMP
	case 0x4c: // jmp $ffff
		op->cycles = 3;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -682,9 +682,15 @@
 		op->cycles = 2;
 		op->failcycles = 3;
 		op->type = R_ANAL_OP_TYPE_CJMP;
-		if (data[1] <= 127)
-			op->jump = addr + data[1] + op->size;
-		else	op->jump = addr - (256 - data[1]) + op->size;
+		if (len > 1) {
+			if (data[1] <= 127) {
+				op->jump = addr + data[1] + op->size;
+			} else {
+				op->jump = addr - (256 - data[1]) + op->size;
+			}
+		} else {
+			op->jump = addr;
+		}
 		op->fail = addr + op->size;
 		// FIXME: add a type of conditional
 		// op->cond = R_ANAL_COND_LE;
```
