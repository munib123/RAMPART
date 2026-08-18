# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 147_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `147_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 908-948 of the vulnerable file.

	int k = (buf[0] & 0xf) + ((buf[1] & 0xf) << 4);
	int d = ((buf[0] >> 4) & 0xf) + 16;
	op->val = k;
	ESIL_A ("0x%x,r%d,=,", k, d);
}

INST_HANDLER (lds) {	// LDS Rd, k
	if (len < 4) {
		return;
	}
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
INST_HANDLER (lds16) {	// LDS Rd, k
	int d = ((buf[0] >> 4) & 0xf) + 16;
	int k = (buf[0] & 0x0f)
		| ((buf[1] << 3) & 0x30)
		| ((buf[1] << 4) & 0x40)
		| (~(buf[1] << 4) & 0x80);
	op->ptr = k;

	// load value from @k
	__generic_ld_st (op, "ram", 0, 0, 0, k, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -925,6 +925,9 @@
 }
 
 INST_HANDLER (sts) {	// STS k, Rr
+	if (len < 4) {
+		return;
+	}
 	int r = ((buf[0] >> 4) & 0xf) | ((buf[1] & 0x1) << 4);
 	int k = (buf[3] << 8) | buf[2];
 	op->ptr = k;
```
