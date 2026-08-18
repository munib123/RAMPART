# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 504_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `504_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1551-1592 of the vulnerable file.

			if (hint) {
				if (hint->opcode) {
					printline ("ophint", "%s\n", hint->opcode);
				}
#if 0
				// addr should not override core->offset + idx.. its silly
				if (hint->addr != UT64_MAX) {
					printline ("addr", "0x%08" PFMT64x "\n", (hint->addr + idx));
				}
#endif
			}
			printline ("prefix", "%" PFMT64u "\n", op.prefix);
			printline ("id", "%d\n", op.id);
#if 0
// no opex here to avoid lot of tests broken..and having json in here is not much useful imho
			if (opexstr && *opexstr) {
				printline ("opex", "%s\n", opexstr);
			}
#endif
			printline ("bytes", NULL, 0);
			for (j = 0; j < size; j++) {
				r_cons_printf ("%02x", buf[j + idx]);
			}
			r_cons_newline ();
			if (op.val != UT64_MAX)
				printline ("val", "0x%08" PFMT64x "\n", op.val);
			if (op.ptr != UT64_MAX)
				printline ("ptr", "0x%08" PFMT64x "\n", op.ptr);
			if (op.refptr != -1)
				printline ("refptr", "%d\n", op.refptr);
			printline ("size", "%d\n", size);
			printline ("sign", "%s\n", r_str_bool (op.sign));
			printline ("type", "%s\n", r_anal_optype_to_string (op.type));
			printline ("cycles", "%d\n", op.cycles);
			if (op.failcycles) {
				printline ("failcycles", "%d\n", op.failcycles);
			}
			{
				const char *t2 = r_anal_optype_to_string (op.type2);
				if (t2 && strcmp (t2, "null")) {
					printline ("type2", "%s\n", t2);
				}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1568,16 +1568,22 @@
 			}
 #endif
 			printline ("bytes", NULL, 0);
-			for (j = 0; j < size; j++) {
-				r_cons_printf ("%02x", buf[j + idx]);
+			int minsz = R_MIN (len, size);
+			minsz = R_MAX (minsz, 0);
+			for (j = 0; j < minsz; j++) {
+				ut8 ch = ((j + idx - 1) > minsz)? 0xff: buf[j + idx];
+				r_cons_printf ("%02x", ch);
 			}
 			r_cons_newline ();
-			if (op.val != UT64_MAX)
+			if (op.val != UT64_MAX) {
 				printline ("val", "0x%08" PFMT64x "\n", op.val);
-			if (op.ptr != UT64_MAX)
+			}
+			if (op.ptr != UT64_MAX) {
 				printline ("ptr", "0x%08" PFMT64x "\n", op.ptr);
-			if (op.refptr != -1)
+			}
+			if (op.refptr != -1) {
 				printline ("refptr", "%d\n", op.refptr);
+			}
 			printline ("size", "%d\n", size);
 			printline ("sign", "%s\n", r_str_bool (op.sign));
 			printline ("type", "%s\n", r_anal_optype_to_string (op.type));
```
