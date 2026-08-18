# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 675_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `675_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 57-97 of the vulnerable file.

	"NTLMSSP_TARGET_TYPE_SERVER",
	"NTLMSSP_TARGET_TYPE_DOMAIN",
	"NTLMSSP_NEGOTIATE_ALWAYS_SIGN",
	"NTLMSSP_RESERVED7",
	"NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED",
	"NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED",
	"NTLMSSP_NEGOTIATE_ANONYMOUS",
	"NTLMSSP_RESERVED8",
	"NTLMSSP_NEGOTIATE_NTLM",
	"NTLMSSP_RESERVED9",
	"NTLMSSP_NEGOTIATE_LM_KEY",
	"NTLMSSP_NEGOTIATE_DATAGRAM",
	"NTLMSSP_NEGOTIATE_SEAL",
	"NTLMSSP_NEGOTIATE_SIGN",
	"NTLMSSP_RESERVED10",
	"NTLMSSP_REQUEST_TARGET",
	"NTLMSSP_NEGOTIATE_OEM",
	"NTLMSSP_NEGOTIATE_UNICODE"
};

void ntlm_print_negotiate_flags(UINT32 flags)
{
	int i;
	const char* str;
	WLog_INFO(TAG, "negotiateFlags \"0x%08"PRIX32"\"", flags);

	for (i = 31; i >= 0; i--)
	{
		if ((flags >> i) & 1)
		{
			str = NTLM_NEGOTIATE_STRINGS[(31 - i)];
			WLog_INFO(TAG, "\t%s (%d),", str, (31 - i));
		}
	}
}

int ntlm_read_message_header(wStream* s, NTLM_MESSAGE_HEADER* header)
{
	if (Stream_GetRemainingLength(s) < 12)
		return -1;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,7 +74,7 @@
 	"NTLMSSP_NEGOTIATE_UNICODE"
 };
 
-void ntlm_print_negotiate_flags(UINT32 flags)
+static void ntlm_print_negotiate_flags(UINT32 flags)
 {
 	int i;
 	const char* str;
@@ -90,7 +90,7 @@
 	}
 }
 
-int ntlm_read_message_header(wStream* s, NTLM_MESSAGE_HEADER* header)
+static int ntlm_read_message_header(wStream* s, NTLM_MESSAGE_HEADER* header)
 {
 	if (Stream_GetRemainingLength(s) < 12)
 		return -1;
@@ -104,19 +104,19 @@
 	return 1;
 }
 
-void ntlm_write_message_header(wStream* s, NTLM_MESSAGE_HEADER* header)
+static void ntlm_write_message_header(wStream* s, NTLM_MESSAGE_HEADER* header)
 {
 	Stream_Write(s, header->Signature, sizeof(NTLM_SIGNATURE));
 	Stream_Write_UINT32(s, header->MessageType);
 }
 
-void ntlm_populate_message_header(NTLM_MESSAGE_HEADER* header, UINT32 MessageType)
+static void ntlm_populate_message_header(NTLM_MESSAGE_HEADER* header, UINT32 MessageType)
 {
 	CopyMemory(header->Signature, NTLM_SIGNATURE, sizeof(NTLM_SIGNATURE));
 	header->MessageType = MessageType;
 }
 
-int ntlm_read_message_fields(wStream* s, NTLM_MESSAGE_FIELDS* fields)
+static int ntlm_read_message_fields(wStream* s, NTLM_MESSAGE_FIELDS* fields)
 {
 	if (Stream_GetRemainingLength(s) < 8)
 		return -1;
@@ -127,7 +127,7 @@
 	return 1;
 }
 
-void ntlm_write_message_fields(wStream* s, NTLM_MESSAGE_FIELDS* fields)
+static void ntlm_write_message_fields(wStream* s, NTLM_MESSAGE_FIELDS* fields)
 {
 	if (fields->MaxLen < 1)
 		fields->MaxLen = fields->Len;
@@ -137,11 +137,13 @@
 	Stream_Write_UINT32(s, fields->BufferOffset); /* BufferOffset (4 bytes) */
 }
 
-int ntlm_read_message_fields_buffer(wStream* s, NTLM_MESSAGE_FIELDS* fields)
+static int ntlm_read_message_fields_buffer(wStream* s, NTLM_MESSAGE_FIELDS* fields)
 {
 	if (fields->Len > 0)
 	{
-		if ((fields->BufferOffset + fields->Len) > Stream_Length(s))
+		const UINT64 offset = (UINT64)fields->BufferOffset + (UINT64)fields->Len;
+
+		if (offset > Stream_Length(s))
 			return -1;
 
 		fields->Buffer = (PBYTE) malloc(fields->Len);
@@ -156,7 +158,7 @@
 	return 1;
 }
 
-void ntlm_write_message_fields_buffer(wStream* s, NTLM_MESSAGE_FIELDS* fields)
+static void ntlm_write_message_fields_buffer(wStream* s, NTLM_MESSAGE_FIELDS* fields)
 {
 	if (fields->Len > 0)
 	{
@@ -165,7 +167,7 @@
 	}
 }
 
-void ntlm_free_message_fields_buffer(NTLM_MESSAGE_FIELDS* fields)
+static void ntlm_free_message_fields_buffer(NTLM_MESSAGE_FIELDS* fields)
 {
 	if (fields)
 	{
@@ -180,7 +182,7 @@
 	}
 }
 
-void ntlm_print_message_fields(NTLM_MESSAGE_FIELDS* fields, const char* name)
+static void ntlm_print_message_fields(NTLM_MESSAGE_FIELDS* fields, const char* name)
 {
 	WLog_DBG(TAG, "%s (Len: %"PRIu16" MaxLen: %"PRIu16" BufferOffset: %"PRIu32")",
 	         name, fields->Len, fields->MaxLen, fields->BufferOffset);
```
