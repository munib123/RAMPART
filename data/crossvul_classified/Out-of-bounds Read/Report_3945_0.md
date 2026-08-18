# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3945_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3945_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 202-242 of the vulnerable file.

	NTLM_NEGOTIATE_MESSAGE* message;
	message = &context->NEGOTIATE_MESSAGE;
	ZeroMemory(message, sizeof(NTLM_NEGOTIATE_MESSAGE));
	s = Stream_New((BYTE*)buffer->pvBuffer, buffer->cbBuffer);

	if (!s)
		return SEC_E_INTERNAL_ERROR;

	if (ntlm_read_message_header(s, (NTLM_MESSAGE_HEADER*)message) < 0)
	{
		Stream_Free(s, FALSE);
		return SEC_E_INVALID_TOKEN;
	}

	if (message->MessageType != MESSAGE_TYPE_NEGOTIATE)
	{
		Stream_Free(s, FALSE);
		return SEC_E_INVALID_TOKEN;
	}

	Stream_Read_UINT32(s, message->NegotiateFlags); /* NegotiateFlags (4 bytes) */

	if (!((message->NegotiateFlags & NTLMSSP_REQUEST_TARGET) &&
	      (message->NegotiateFlags & NTLMSSP_NEGOTIATE_NTLM) &&
	      (message->NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE)))
	{
		Stream_Free(s, FALSE);
		return SEC_E_INVALID_TOKEN;
	}

	context->NegotiateFlags = message->NegotiateFlags;

	/* only set if NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED is set */

	if (ntlm_read_message_fields(s, &(message->DomainName)) < 0) /* DomainNameFields (8 bytes) */
	{
		Stream_Free(s, FALSE);
		return SEC_E_INVALID_TOKEN;
	}

	/* only set if NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED is set */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -219,6 +219,11 @@
 		return SEC_E_INVALID_TOKEN;
 	}
 
+	if (Stream_GetRemainingLength(s) < 4)
+	{
+		Stream_Free(s, FALSE);
+		return SEC_E_INVALID_TOKEN;
+	}
 	Stream_Read_UINT32(s, message->NegotiateFlags); /* NegotiateFlags (4 bytes) */
 
 	if (!((message->NegotiateFlags & NTLMSSP_REQUEST_TARGET) &&
```
