# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 139_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `139_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 895-935 of the vulnerable file.

			? (!offset ? 1 : 3)		// LDD
			: (buf[0] & 0x3) == 0
				? 1			// LD Rd, X
				: (buf[0] & 0x3) == 1
					? 2		// LD Rd, X+
					: 3;		// LD Rd, -X
	if (!STR_BEGINS (cpu->model, "ATxmega") && op->cycles > 1) {
		// AT*mega optimizes 1 cycle!
		op->cycles--;
	}
}

INST_HANDLER (ldi) {	// LDI Rd, K
	int k = (buf[0] & 0xf) + ((buf[1] & 0xf) << 4);
	int d = ((buf[0] >> 4) & 0xf) + 16;
	op->val = k;
	ESIL_A ("0x%x,r%d,=,", k, d);
}

INST_HANDLER (lds) {	// LDS Rd, k
	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];
	op->ptr = k;

	// load value from RAMPD:k
	__generic_ld_st (op, "ram", 0, 1, 0, k, 0);
	ESIL_A ("r%d,=,", d);
}

INST_HANDLER (sts) {	// STS k, Rr
	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
	int k = (buf[3] << 8) | buf[2];
	op->ptr = k;

	ESIL_A ("r%d,", r);
	__generic_ld_st (op, "ram", 0, 1, 0, k, 1);

	op->cycles = 2;
}

#if 0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -912,6 +912,9 @@
 }
 
 INST_HANDLER (lds) {	// LDS Rd, k
+	if (len < 4) {
+		return;
+	}
 	int d = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
 	int k = (buf[3] << 8) | buf[2];
 	op->ptr = k;
```
