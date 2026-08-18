# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_13
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_13`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 772-812 of the vulnerable file.

		SC_AC_OP_READ, SC_AC_OP_UPDATE, SC_AC_OP_WRITE,
		SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE,
		-1, SC_AC_OP_ERASE, -1};
	const int efi_idx[8] = { /* internal EF used for RSA keys */
		SC_AC_OP_READ, SC_AC_OP_ERASE, SC_AC_OP_UPDATE,
		SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE,
		-1, SC_AC_OP_ERASE, -1};

	u8		bValue;
	int		i;
	int		iKeyRef = 0;
	int		iMethod;
	int		iPinCount;
	int		iOffset = 0;
	int		iOperation;
	const int*	p_idx;

	/* Check all sub-AC definitions within the total AC */
	while (len > 1) {				/* minimum length = 2 */
		int	iACLen   = buf[iOffset] & 0x0F;

		iPinCount = -1;			/* default no pin required */
		iMethod = SC_AC_NONE;		/* default no authentication required */

		if (buf[iOffset] & 0X80) { /* AC in adaptive coding */
			/* Evaluates only the command-byte, not the optional P1/P2/Option bytes */
			int	iParmLen = 1;			/* command-byte is always present */
			int	iKeyLen  = 0;			/* Encryption key is optional */

			if (buf[iOffset]   & 0x20) iKeyLen++;
			if (buf[iOffset+1] & 0x40) iParmLen++;
			if (buf[iOffset+1] & 0x20) iParmLen++;
			if (buf[iOffset+1] & 0x10) iParmLen++;
			if (buf[iOffset+1] & 0x08) iParmLen++;

			/* Get KeyNumber if available */
			if(iKeyLen) {
				int iSC = buf[iOffset+iACLen];

				switch( (iSC>>5) & 0x03 ){
				case 0:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -789,6 +789,8 @@
 	/* Check all sub-AC definitions within the total AC */
 	while (len > 1) {				/* minimum length = 2 */
 		int	iACLen   = buf[iOffset] & 0x0F;
+		if ((size_t) iACLen > len)
+			break;
 
 		iPinCount = -1;			/* default no pin required */
 		iMethod = SC_AC_NONE;		/* default no authentication required */
@@ -806,7 +808,10 @@
 
 			/* Get KeyNumber if available */
 			if(iKeyLen) {
-				int iSC = buf[iOffset+iACLen];
+				int iSC;
+				if (len < 1+iACLen)
+					break;
+				iSC = buf[iOffset+iACLen];
 
 				switch( (iSC>>5) & 0x03 ){
 				case 0:
@@ -825,11 +830,15 @@
 
 			/* Get PinNumber if available */
 			if (iACLen > (1+iParmLen+iKeyLen)) {  /* check via total length if pin is present */
+				if (len < 1+1+1+iParmLen)
+					break;
 				iKeyRef = buf[iOffset+1+1+iParmLen];  /* PTL + AM-header + parameter-bytes */
 				iMethod = SC_AC_CHV;
 			}
 
 			/* Convert SETCOS command to OpenSC command group */
+			if (len < 1+2)
+				break;
 			switch(buf[iOffset+2]){
 			case 0x2A:			/* crypto operation */
 				iOperation = SC_AC_OP_CRYPTO;
@@ -863,7 +872,10 @@
 			iPinCount = iACLen - 1;		
 
 			if (buf[iOffset] & 0x20) {
-				int iSC = buf[iOffset + iACLen];
+				int iSC;
+				if (len < 1 + iACLen)
+					break;
+				iSC = buf[iOffset + iACLen];
 
 				switch( (iSC>>5) & 0x03 ) {
 				case 0:
@@ -884,6 +896,8 @@
 
 			/* Pin present ? */
 			if ( iPinCount > 0 ) {
+				if (len < 1 + 2)
+					break;
 				iKeyRef = buf[iOffset + 2];	/* pin ref */
 				iMethod = SC_AC_CHV;
 			}
```
