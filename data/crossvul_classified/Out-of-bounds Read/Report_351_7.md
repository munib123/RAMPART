# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_7
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_7`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 391-431 of the vulnerable file.

	int		i, rc;

	memset(file, 0, sizeof(*file));
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		sc_file_add_acl_entry(file, i, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);

	end = buf + buflen;
	for (sp = buf; sp + 2 < end; sp = next) {
		next = sp + 2 + sp[1];
		if (next > end)
			break;
		if (sp[0] == 0x84) {
			/* ignore if name is longer than what it should be */
			if (sp[1] > sizeof(file->name))
				continue;
			memset(file->name, 0, sizeof(file->name));
			memcpy(file->name, sp+2, sp[1]);
		} else
		if (sp[0] == 0x85) {
			unsigned int	ac[3], n;

			file->id = (sp[4] << 8) | sp[5];
			file->size = (sp[8] << 8) | sp[9];
			file->record_length = sp[7];

			/* Map ACLs. Note the third AC byte is
			 * valid of EFs only */
			for (n = 0; n < 3; n++)
				ac[n] = (sp[10+2*n] << 8) | sp[11+2*n];

			/* Examine file type */
			switch (sp[6] & 7) {
			case 0x01: case 0x02: case 0x03: case 0x04:
			case 0x05: case 0x06: case 0x07:
				file->type = SC_FILE_TYPE_WORKING_EF;
				file->ef_structure = sp[6] & 7;
				ac_to_acl(ac[0], file, SC_AC_OP_UPDATE);
				ac_to_acl(ac[1], file, SC_AC_OP_WRITE);
				ac_to_acl(ac[2], file, SC_AC_OP_READ);
				break;
			case 0x00: /* 0x38 is DF */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -408,6 +408,9 @@
 		} else
 		if (sp[0] == 0x85) {
 			unsigned int	ac[3], n;
+
+			if (sp + 11 + 2*3 >= end)
+				break;
 
 			file->id = (sp[4] << 8) | sp[5];
 			file->size = (sp[8] << 8) | sp[9];
```
