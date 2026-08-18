# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3943_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3943_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 107-147 of the vulnerable file.

/**
 * Print VERSION structure.
 * VERSION @msdn{cc236654}
 * @param s
 */

void ntlm_print_version_info(NTLM_VERSION_INFO* versionInfo)
{
	WLog_INFO(TAG, "VERSION ={");
	WLog_INFO(TAG, "\tProductMajorVersion: %" PRIu8 "", versionInfo->ProductMajorVersion);
	WLog_INFO(TAG, "\tProductMinorVersion: %" PRIu8 "", versionInfo->ProductMinorVersion);
	WLog_INFO(TAG, "\tProductBuild: %" PRIu16 "", versionInfo->ProductBuild);
	WLog_INFO(TAG, "\tReserved: 0x%02" PRIX8 "%02" PRIX8 "%02" PRIX8 "", versionInfo->Reserved[0],
	          versionInfo->Reserved[1], versionInfo->Reserved[2]);
	WLog_INFO(TAG, "\tNTLMRevisionCurrent: 0x%02" PRIX8 "", versionInfo->NTLMRevisionCurrent);
}

static int ntlm_read_ntlm_v2_client_challenge(wStream* s, NTLMv2_CLIENT_CHALLENGE* challenge)
{
	size_t size;
	Stream_Read_UINT8(s, challenge->RespType);
	Stream_Read_UINT8(s, challenge->HiRespType);
	Stream_Read_UINT16(s, challenge->Reserved1);
	Stream_Read_UINT32(s, challenge->Reserved2);
	Stream_Read(s, challenge->Timestamp, 8);
	Stream_Read(s, challenge->ClientChallenge, 8);
	Stream_Read_UINT32(s, challenge->Reserved3);
	size = Stream_Length(s) - Stream_GetPosition(s);

	if (size > UINT32_MAX)
		return -1;

	challenge->cbAvPairs = size;
	challenge->AvPairs = (NTLM_AV_PAIR*)malloc(challenge->cbAvPairs);

	if (!challenge->AvPairs)
		return -1;

	Stream_Read(s, challenge->AvPairs, size);
	return 1;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,6 +124,9 @@
 static int ntlm_read_ntlm_v2_client_challenge(wStream* s, NTLMv2_CLIENT_CHALLENGE* challenge)
 {
 	size_t size;
+	if (Stream_GetRemainingLength(s) < 28)
+		return -1;
+
 	Stream_Read_UINT8(s, challenge->RespType);
 	Stream_Read_UINT8(s, challenge->HiRespType);
 	Stream_Read_UINT16(s, challenge->Reserved1);
@@ -163,6 +166,8 @@
 
 int ntlm_read_ntlm_v2_response(wStream* s, NTLMv2_RESPONSE* response)
 {
+	if (Stream_GetRemainingLength(s) < 16)
+		return -1;
 	Stream_Read(s, response->Response, 16);
 	return ntlm_read_ntlm_v2_client_challenge(s, &(response->Challenge));
 }
```
