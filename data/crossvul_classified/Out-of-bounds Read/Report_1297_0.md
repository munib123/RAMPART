# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1297_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1297_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 851-891 of the vulnerable file.

			}
			sc_file_add_acl_entry(file, iOperation, iMethod, iKeyRef);
		}
		else { /* AC in simple coding */
			   /* Initial AC is treated as an operational AC */

			/* Get specific Cmd groups for specified file-type */
			switch (file->type) {
			case SC_FILE_TYPE_DF:            /* DF */
				p_idx = df_idx;
				break;
			case SC_FILE_TYPE_INTERNAL_EF:   /* EF for RSA keys */
				p_idx = efi_idx;
				break;
			default:                         /* EF */
				p_idx = ef_idx;
				break;
			}

			/* Encryption key present ? */
			iPinCount = iACLen - 1;		

			if (buf[iOffset] & 0x20) {
				int iSC;
				if (len < 1 + (size_t)iACLen)
					break;
				iSC = buf[iOffset + iACLen];

				switch( (iSC>>5) & 0x03 ) {
				case 0:
					iMethod = SC_AC_TERM;		/* key authentication */
					break;
				case 1:
					iMethod = SC_AC_AUT;		/* key authentication  */
					break;
				case 2:
				case 3:
					iMethod = SC_AC_PRO;		/* secure messaging */
					break;
				}
				iKeyRef = iSC & 0x1F;			/* get key number */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -868,7 +868,7 @@
 			}
 
 			/* Encryption key present ? */
-			iPinCount = iACLen - 1;		
+			iPinCount = iACLen > 0 ? iACLen - 1 : 0;
 
 			if (buf[iOffset] & 0x20) {
 				int iSC;
```
