# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3955_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3955_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1235-1275 of the vulnerable file.

	/* compute MAC and check it */
	if (Stream_GetRemainingLength(s) < 16)
		goto out_free_blob;

	if (!security_mac_data(license->MacSaltKey, calBlob->data, calBlob->length, computedMac))
		goto out_free_blob;

	if (memcmp(computedMac, Stream_Pointer(s), sizeof(computedMac)) != 0)
	{
		WLog_ERR(TAG, "new or upgrade license MAC mismatch");
		goto out_free_blob;
	}

	if (!Stream_SafeSeek(s, 16))
		goto out_free_blob;

	licenseStream = Stream_New(calBlob->data, calBlob->length);
	if (!licenseStream)
		goto out_free_blob;

	Stream_Read_UINT16(licenseStream, os_minor);
	Stream_Read_UINT16(licenseStream, os_major);

	/* Scope */
	Stream_Read_UINT32(licenseStream, cbScope);
	if (Stream_GetRemainingLength(licenseStream) < cbScope)
		goto out_free_stream;
#ifdef WITH_DEBUG_LICENSE
	WLog_DBG(TAG, "Scope:");
	winpr_HexDump(TAG, WLOG_DEBUG, Stream_Pointer(licenseStream), cbScope);
#endif
	Stream_Seek(licenseStream, cbScope);

	/* CompanyName */
	Stream_Read_UINT32(licenseStream, cbCompanyName);
	if (Stream_GetRemainingLength(licenseStream) < cbCompanyName)
		goto out_free_stream;
#ifdef WITH_DEBUG_LICENSE
	WLog_DBG(TAG, "Company name:");
	winpr_HexDump(TAG, WLOG_DEBUG, Stream_Pointer(licenseStream), cbCompanyName);
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1252,6 +1252,9 @@
 	if (!licenseStream)
 		goto out_free_blob;
 
+	if (Stream_GetRemainingLength(licenseStream) < 8)
+		goto out_free_stream;
+
 	Stream_Read_UINT16(licenseStream, os_minor);
 	Stream_Read_UINT16(licenseStream, os_major);
 
@@ -1266,6 +1269,8 @@
 	Stream_Seek(licenseStream, cbScope);
 
 	/* CompanyName */
+	if (Stream_GetRemainingLength(licenseStream) < 4)
+		goto out_free_stream;
 	Stream_Read_UINT32(licenseStream, cbCompanyName);
 	if (Stream_GetRemainingLength(licenseStream) < cbCompanyName)
 		goto out_free_stream;
@@ -1276,6 +1281,8 @@
 	Stream_Seek(licenseStream, cbCompanyName);
 
 	/* productId */
+	if (Stream_GetRemainingLength(licenseStream) < 4)
+		goto out_free_stream;
 	Stream_Read_UINT32(licenseStream, cbProductId);
 	if (Stream_GetRemainingLength(licenseStream) < cbProductId)
 		goto out_free_stream;
@@ -1286,6 +1293,8 @@
 	Stream_Seek(licenseStream, cbProductId);
 
 	/* licenseInfo */
+	if (Stream_GetRemainingLength(licenseStream) < 4)
+		goto out_free_stream;
 	Stream_Read_UINT32(licenseStream, cbLicenseInfo);
 	if (Stream_GetRemainingLength(licenseStream) < cbLicenseInfo)
 		goto out_free_stream;
```
