# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3185_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3185_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 360-400 of the vulnerable file.

		reg = argReg;
		switch (type[0]) {
		case 'D':
		case 'J':
			argReg += 2;
			break;
		default:
			argReg += 1;
			break;
		}
		if (name) {
			debug_locals[reg].name = name;
			debug_locals[reg].descriptor = type;
			debug_locals[reg].signature = NULL;
			debug_locals[reg].startAddress = address;
			debug_locals[reg].live = true;
		}
		--parameters_size;
	}

	ut8 opcode = *(p4++) & 0xff;
	while (keep) {
		switch (opcode) {
		case 0x0: // DBG_END_SEQUENCE
			keep = false;
			break;
		case 0x1: // DBG_ADVANCE_PC
			{
			ut64 addr_diff;
			p4 = r_uleb128 (p4, p4_end - p4, &addr_diff);
			address += addr_diff;
			}
			break;
		case 0x2: // DBG_ADVANCE_LINE
			{
			st64 line_diff = r_sleb128 (&p4, p4_end);
			line += line_diff;
			}
			break;	
		case 0x3: // DBG_START_LOCAL
			{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -377,6 +377,9 @@
 		--parameters_size;
 	}
 
+	if (p4 <= 0) {
+		return;
+	}
 	ut8 opcode = *(p4++) & 0xff;
 	while (keep) {
 		switch (opcode) {
```
