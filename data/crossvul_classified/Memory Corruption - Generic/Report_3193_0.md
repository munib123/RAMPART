# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3193_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3193_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 9-49 of the vulnerable file.


#include <dalvik/opcode.h>

static int dalvik_disassemble (RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int vA, vB, vC, payload = 0, i = (int) buf[0];
	int size = dalvik_opcodes[i].len;
	char str[1024], *strasm;
	ut64 offset;
	const char *flag_str; 

	op->buf_asm[0] = 0;
	if (buf[0] == 0x00) { /* nop */
		switch (buf[1]) {
		case 0x01: /* packed-switch-payload */
			// ushort size
			// int first_key
			// int[size] = relative offsets
			{
				unsigned short array_size = buf[2] | (buf[3] << 8);
				int first_key = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);
				sprintf (op->buf_asm, "packed-switch-payload %d, %d", array_size, first_key);
				size = 8;
				payload = 2 * (array_size * 2);
				len = 0;
			}
			break;
		case 0x02: /* sparse-switch-payload */
			// ushort size
			// int[size] keys
			// int[size] relative offsets
			{
				unsigned short array_size = buf[2] | (buf[3] << 8);
				sprintf (op->buf_asm, "sparse-switch-payload %d", array_size);
				size = 4;
				payload = 2 * (array_size*4);
				len = 0;
			}
			break;
		case 0x03: /* fill-array-data-payload */
			// element_width = 2 bytes ushort little endian
			// size = 4 bytes uint
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
 			{
 				unsigned short array_size = buf[2] | (buf[3] << 8);
 				int first_key = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);
-				sprintf (op->buf_asm, "packed-switch-payload %d, %d", array_size, first_key);
+				snprintf (op->buf_asm, sizeof(op->buf_asm), "packed-switch-payload %d, %d", array_size, first_key);
 				size = 8;
 				payload = 2 * (array_size * 2);
 				len = 0;
@@ -38,7 +38,7 @@
 			// int[size] relative offsets
 			{
 				unsigned short array_size = buf[2] | (buf[3] << 8);
-				sprintf (op->buf_asm, "sparse-switch-payload %d", array_size);
+				snprintf (op->buf_asm, sizeof (op->buf_asm), "sparse-switch-payload %d", array_size);
 				size = 4;
 				payload = 2 * (array_size*4);
 				len = 0;
@@ -74,37 +74,37 @@
 		case fmtopvAvB:
 			vA = buf[1] & 0x0f;
 			vB = (buf[1] & 0xf0) >> 4;
-			sprintf (str, " v%i, v%i", vA, vB);
+			snprintf (str, sizeof (str), " v%i, v%i", vA, vB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAAvBBBB:
 			vA = (int) buf[1];
 			vB = (buf[3] << 8) | buf[2];
-			sprintf (str, " v%i, v%i", vA, vB);
+			snprintf (str, sizeof (str), " v%i, v%i", vA, vB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAAAAvBBBB: // buf[1] seems useless :/
 			vA = (buf[3] << 8) | buf[2];
 			vB = (buf[5] << 8) | buf[4];
-			sprintf (str, " v%i, v%i", vA, vB);
+			snprintf (str, sizeof (str), " v%i, v%i", vA, vB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAA:
 			vA = (int) buf[1];
-			sprintf (str, " v%i", vA);
+			snprintf (str, sizeof (str), " v%i", vA);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAcB:
 			vA = buf[1] & 0x0f;
 			vB = (buf[1] & 0xf0) >> 4;
-			sprintf (str, " v%i, %#x", vA, vB);
+			snprintf (str, sizeof (str), " v%i, %#x", vA, vB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAAcBBBB:
 			vA = (int) buf[1];
 			{
 				short sB = (buf[3] << 8) | buf[2];
-				sprintf (str, " v%i, %#04hx", vA, sB);
+				snprintf (str, sizeof (str), " v%i, %#04hx", vA, sB);
 				strasm = r_str_concat (strasm, str);
 			}
 			break;
@@ -137,33 +137,33 @@
 				((llint)buf[6] << 32) | ((llint)buf[7] << 40)|
 				((llint)buf[8] << 48) | ((llint)buf[9] << 56);
 			#undef llint
-			sprintf (str, " v%i:v%i, 0x%"PFMT64x, vA, vA + 1, lB);
+			snprintf (str, sizeof (str), " v%i:v%i, 0x%"PFMT64x, vA, vA + 1, lB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAAvBBvCC:
 			vA = (int) buf[1];
 			vB = (int) buf[2];
 			vC = (int) buf[3];
-			sprintf (str, " v%i, v%i, v%i", vA, vB, vC);
+			snprintf (str, sizeof (str), " v%i, v%i, v%i", vA, vB, vC);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAAvBBcCC:
 			vA = (int) buf[1];
 			vB = (int) buf[2];
 			vC = (int) buf[3];
-			sprintf (str, " v%i, v%i, %#x", vA, vB, vC);
+			snprintf (str, sizeof (str), " v%i, v%i, %#x", vA, vB, vC);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAvBcCCCC:
 			vA = buf[1] & 0x0f;
 			vB = (buf[1] & 0xf0) >> 4;
 			vC = (buf[3] << 8) | buf[2];
-			sprintf (str, " v%i, v%i, %#x", vA, vB, vC);
+			snprintf (str, sizeof (str), " v%i, v%i, %#x", vA, vB, vC);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtoppAA:
 			vA = (char) buf[1];
-			//sprintf (str, " %i", vA*2); // vA : word -> byte
+			//snprintf (str, sizeof (str), " %i", vA*2); // vA : word -> byte
 			snprintf (str, sizeof (str), " 0x%08"PFMT64x, a->pc + (vA * 2)); // vA : word -> byte
 			strasm = r_str_concat (strasm, str);
 			break;
@@ -175,13 +175,13 @@
 		case fmtopvAApBBBB: // if-*z
 			vA = (int) buf[1];
 			vB = (int) (buf[3] << 8 | buf[2]);
-			//sprintf (str, " v%i, %i", vA, vB);
+			//snprintf (str, sizeof (str), " v%i, %i", vA, vB);
 			snprintf (str, sizeof (str), " v%i, 0x%08"PFMT64x, vA, a->pc + (vB * 2));
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtoppAAAAAAAA:
 			vA = (int) (buf[2] | (buf[3] << 8) | (buf[4] << 16) | (buf[5] << 24));
-			//sprintf (str, " %#08x", vA*2); // vA: word -> byte
+			//snprintf (str, sizeof (str), " %#08x", vA*2); // vA: word -> byte
 			snprintf (str, sizeof (str), " 0x%08"PFMT64x, a->pc + (vA*2)); // vA : word -> byte
 			strasm = r_str_concat (strasm, str);
 			break;
@@ -189,7 +189,7 @@
 			vA = buf[1] & 0x0f;
 			vB = (buf[1] & 0xf0) >> 4;
 			vC = (int) (buf[3] << 8 | buf[2]);
-			//sprintf (str, " v%i, v%i, %i", vA, vB, vC);
+			//snprintf (str, sizeof (str), " v%i, v%i, %i", vA, vB, vC);
 			snprintf (str, sizeof (str)," v%i, v%i, 0x%08"PFMT64x, vA, vB, a->pc + (vC * 2));
 			strasm = r_str_concat (strasm, str);
 			break;
@@ -205,23 +205,23 @@
 			*str = 0;
 			switch (vA) {
 			case 1:
-				sprintf (str, " {v%i}", buf[4] & 0x0f);
+				snprintf (str, sizeof (str), " {v%i}", buf[4] & 0x0f);
 				break;
 			case 2:
-				sprintf (str, " {v%i, v%i}", buf[4] & 0x0f, (buf[4] & 0xf0) >> 4);
+				snprintf (str, sizeof (str), " {v%i, v%i}", buf[4] & 0x0f, (buf[4] & 0xf0) >> 4);
 				break;
 			case 3:
-				sprintf (str, " {v%i, v%i, v%i}", buf[4] & 0x0f, (buf[4] & 0xf0) >> 4, buf[5] & 0x0f);
+				snprintf (str, sizeof (str), " {v%i, v%i, v%i}", buf[4] & 0x0f, (buf[4] & 0xf0) >> 4, buf[5] & 0x0f);
 				break;
 			case 4:
-				sprintf (str, " {v%i, v%i, v%i, v%i}", buf[4] & 0x0f,
+				snprintf (str, sizeof (str), " {v%i, v%i, v%i, v%i}", buf[4] & 0x0f,
 						(buf[4] & 0xf0) >> 4, buf[5] & 0x0f, (buf[5] & 0xf0) >> 4);
 				break;
 			default:
-				sprintf (str, " {}");
-			}
-			strasm = r_str_concat (strasm, str);
-			sprintf (str, ", [%04x]", vB);
+				snprintf (str, sizeof (str), " {}");
+			}
+			strasm = r_str_concat (strasm, str);
+			snprintf (str, sizeof (str), ", [%04x]", vB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtoptinlineIR:
@@ -229,7 +229,7 @@
 			vA = (int) buf[1];
 			vB = (buf[3] << 8) | buf[2];
 			vC = (buf[5] << 8) | buf[4];
-			sprintf (str, " {v%i..v%i}, [%04x]", vC, vC + vA - 1, vB);
+			snprintf (str, sizeof (str), " {v%i..v%i}, [%04x]", vC, vC + vA - 1, vB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtoptinvokeVS:
@@ -237,25 +237,25 @@
 			vB = (buf[3] << 8) | buf[2];
 			switch (vA) {
 			case 1:
-				sprintf (str, " {v%i}", buf[4] & 0x0f);
+				snprintf (str, sizeof (str), " {v%i}", buf[4] & 0x0f);
 				break;
 			case 2:
-				sprintf (str, " {v%i, v%i}", buf[4] & 0x0f, (buf[4] & 0xf0) >> 4);
+				snprintf (str, sizeof (str), " {v%i, v%i}", buf[4] & 0x0f, (buf[4] & 0xf0) >> 4);
 				break;
 			case 3:
-				sprintf (str, " {v%i, v%i, v%i}", buf[4] & 0x0f,
+				snprintf (str, sizeof (str), " {v%i, v%i, v%i}", buf[4] & 0x0f,
 						(buf[4] & 0xf0) >> 4, buf[5] & 0x0f);
 				break;
 			case 4:
-				sprintf (str, " {v%i, v%i, v%i, v%i}", buf[4] & 0x0f,
+				snprintf (str, sizeof (str), " {v%i, v%i, v%i, v%i}", buf[4] & 0x0f,
 						(buf[4] & 0xf0) >> 4, buf[5] & 0x0f, (buf[5] & 0xf0) >> 4);
 				break;
 			default:
-				sprintf (str, " {}");
-				break;
-			}
-			strasm = r_str_concat (strasm, str);
-			sprintf (str, ", [%04x]", vB);
+				snprintf (str, sizeof (str), " {}");
+				break;
+			}
+			strasm = r_str_concat (strasm, str);
+			snprintf (str, sizeof (str), ", [%04x]", vB);
 			strasm = r_str_concat (strasm, str);
 			break;
 		case fmtopvAAtBBBB: // "sput-*"
@@ -264,23 +264,23 @@
 			if (buf[0] == 0x1a) {
 				offset = R_ASM_GET_OFFSET (a, 's', vB);
 				if (offset == -1) {
-					sprintf (str, " v%i, string+%i", vA, vB);
+					snprintf (str, sizeof (str), " v%i, string+%i", vA, vB);
 				} else {
-					sprintf (str, " v%i, 0x%"PFMT64x, vA, offset);
+					snprintf (str, sizeof (str), " v%i, 0x%"PFMT64x, vA, offset);
 				}
 			} else if (buf[0] == 0x1c || buf[0] == 0x1f || buf[0] == 0x22) {
 				flag_str = R_ASM_GET_NAME (a, 'c', vB);
 				if (!flag_str) {
-					sprintf (str, " v%i, class+%i", vA, vB);
+					snprintf (str, sizeof (str), " v%i, class+%i", vA, vB);
 				} else {
-					sprintf (str, " v%i, %s", vA, flag_str);
... (diff truncated)
```
