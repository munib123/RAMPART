# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5628_2
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5628_2`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1851-1892 of the vulnerable file.

	    return CL_EMEM;
	}

	/* try to detect UPX code */
	if(cli_memstr(UPX_NRV2B, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2B, 24, epbuff + 0x69 + 8, 13)) {
	    cli_dbgmsg("UPX: Looks like a NRV2B decompression routine\n");
	    upxfn = upx_inflate2b;
	} else if(cli_memstr(UPX_NRV2D, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2D, 24, epbuff + 0x69 + 8, 13)) {
	    cli_dbgmsg("UPX: Looks like a NRV2D decompression routine\n");
	    upxfn = upx_inflate2d;
	} else if(cli_memstr(UPX_NRV2E, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2E, 24, epbuff + 0x69 + 8, 13)) {
	    cli_dbgmsg("UPX: Looks like a NRV2E decompression routine\n");
	    upxfn = upx_inflate2e;
	}

	if(upxfn) {
	    int skew = cli_readint32(epbuff + 2) - EC32(optional_hdr32.ImageBase) - exe_sections[i + 1].rva;

	    if(epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff) { /* FIXME: legit skews?? */
		skew = 0; 
		if(upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)
		    upx_success = 1;

	    } else {
		cli_dbgmsg("UPX: UPX1 seems skewed by %d bytes\n", skew);
		if(upxfn(src + skew, ssize - skew, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep-skew) >= 0 || upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)
		    upx_success = 1;
	    }

	    if(upx_success)
		cli_dbgmsg("UPX: Successfully decompressed\n");
	    else
		cli_dbgmsg("UPX: Preferred decompressor failed\n");
	}

	if(!upx_success && upxfn != upx_inflate2b) {
	    if(upx_inflate2b(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) == -1 && upx_inflate2b(src + 0x15, ssize - 0x15, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep - 0x15) == -1) {

		cli_dbgmsg("UPX: NRV2B decompressor failed\n");
	    } else {
		upx_success = 1;
		cli_dbgmsg("UPX: Successfully decompressed with NRV2B\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1868,13 +1868,21 @@
 
 	    if(epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff) { /* FIXME: legit skews?? */
 		skew = 0; 
-		if(upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)
-		    upx_success = 1;
-
-	    } else {
+	    }
+	    else if(skew > ssize) {
+		/* Ignore suggested skew larger than section size */
+		cli_dbgmsg("UPX: Ignoring bad skew of %d bytes\n", skew);
+		skew = 0;
+	    }
+	    else {
 		cli_dbgmsg("UPX: UPX1 seems skewed by %d bytes\n", skew);
-		if(upxfn(src + skew, ssize - skew, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep-skew) >= 0 || upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)
-		    upx_success = 1;
+	    }
+
+	    if(upxfn(src + skew, ssize - skew, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep-skew) >= 0 || upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0) {
+		upx_success = 1;
+	    }
+	    else if(skew && (upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)) {
+		upx_success = 1;
 	    }
 
 	    if(upx_success)
```
