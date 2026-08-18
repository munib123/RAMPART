# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 344_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `344_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 391-431 of the vulnerable file.

		apdu.p2 = 0x0C; 
		apdu.cse = (pathlen == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
	}

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r || file_out == NULL) SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);

	if (apdu.resplen < 1 || apdu.resp[0] != 0x62){
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "received invalid template %02X\n", apdu.resp[0]);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	file = sc_file_new();
	if (file == NULL) SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	*file_out = file;
	file->path = *in_path;

	for(i=2; i+1<apdu.resplen && i+1+apdu.resp[i+1]<apdu.resplen; i+=2+apdu.resp[i+1]){
		int j, len=apdu.resp[i+1];
		unsigned char type=apdu.resp[i], *d=apdu.resp+i+2;

		switch (type) {
		case 0x80:
		case 0x81:
			file->size=0;
			for(j=0; j<len; ++j) file->size = (file->size<<8) | d[j];
			break;
		case 0x82:
			file->shareable = (d[0] & 0x40) ? 1 : 0;
			file->ef_structure = d[0] & 7;
			switch ((d[0]>>3) & 7) {
			case 0: file->type = SC_FILE_TYPE_WORKING_EF; break;
			case 7: file->type = SC_FILE_TYPE_DF; break;
			default:
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "invalid file type %02X in file descriptor\n", d[0]);
				SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
			}
			break;
		case 0x83:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -408,7 +408,7 @@
 	file->path = *in_path;
 
 	for(i=2; i+1<apdu.resplen && i+1+apdu.resp[i+1]<apdu.resplen; i+=2+apdu.resp[i+1]){
-		int j, len=apdu.resp[i+1];
+		size_t j, len=apdu.resp[i+1];
 		unsigned char type=apdu.resp[i], *d=apdu.resp+i+2;
 
 		switch (type) {
@@ -432,8 +432,8 @@
 			file->id = (d[0]<<8) | d[1];
 			break;
 		case 0x84:
-			memcpy(file->name, d, len);
-			file->namelen = len;
+			file->namelen = MIN(sizeof file->name, len);
+			memcpy(file->name, d, file->namelen);
 			break;
 		case 0x86:
 			sc_file_set_sec_attr(file, d, len); 
```
