# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3944_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3944_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 664-704 of the vulnerable file.

	CopyMemory(context->ChallengeMessage.pvBuffer, Stream_Buffer(s), length);
#ifdef WITH_DEBUG_NTLM
	WLog_DBG(TAG, "CHALLENGE_MESSAGE (length = %d)", length);
	winpr_HexDump(TAG, WLOG_DEBUG, context->ChallengeMessage.pvBuffer,
	              context->ChallengeMessage.cbBuffer);
	ntlm_print_negotiate_flags(message->NegotiateFlags);

	if (message->NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
		ntlm_print_version_info(&(message->Version));

	ntlm_print_message_fields(&(message->TargetName), "TargetName");
	ntlm_print_message_fields(&(message->TargetInfo), "TargetInfo");
#endif
	context->state = NTLM_STATE_AUTHENTICATE;
	Stream_Free(s, FALSE);
	return SEC_I_CONTINUE_NEEDED;
}

SECURITY_STATUS ntlm_read_AuthenticateMessage(NTLM_CONTEXT* context, PSecBuffer buffer)
{
	wStream* s;
	size_t length;
	UINT32 flags;
	NTLM_AV_PAIR* AvFlags;
	UINT32 PayloadBufferOffset;
	NTLM_AUTHENTICATE_MESSAGE* message;
	SSPI_CREDENTIALS* credentials = context->credentials;
	flags = 0;
	AvFlags = NULL;
	message = &context->AUTHENTICATE_MESSAGE;
	ZeroMemory(message, sizeof(NTLM_AUTHENTICATE_MESSAGE));
	s = Stream_New((BYTE*)buffer->pvBuffer, buffer->cbBuffer);

	if (!s)
		return SEC_E_INTERNAL_ERROR;

	if (ntlm_read_message_header(s, (NTLM_MESSAGE_HEADER*)message) < 0)
	{
		Stream_Free(s, FALSE);
		return SEC_E_INVALID_TOKEN;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -681,15 +681,15 @@
 
 SECURITY_STATUS ntlm_read_AuthenticateMessage(NTLM_CONTEXT* context, PSecBuffer buffer)
 {
+	SECURITY_STATUS status = SEC_E_INVALID_TOKEN;
 	wStream* s;
 	size_t length;
-	UINT32 flags;
-	NTLM_AV_PAIR* AvFlags;
+	UINT32 flags = 0;
+	NTLM_AV_PAIR* AvFlags = NULL;
 	UINT32 PayloadBufferOffset;
 	NTLM_AUTHENTICATE_MESSAGE* message;
 	SSPI_CREDENTIALS* credentials = context->credentials;
-	flags = 0;
-	AvFlags = NULL;
+
 	message = &context->AUTHENTICATE_MESSAGE;
 	ZeroMemory(message, sizeof(NTLM_AUTHENTICATE_MESSAGE));
 	s = Stream_New((BYTE*)buffer->pvBuffer, buffer->cbBuffer);
@@ -698,130 +698,85 @@
 		return SEC_E_INTERNAL_ERROR;
 
 	if (ntlm_read_message_header(s, (NTLM_MESSAGE_HEADER*)message) < 0)
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (message->MessageType != MESSAGE_TYPE_AUTHENTICATE)
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields(s, &(message->LmChallengeResponse)) <
 	    0) /* LmChallengeResponseFields (8 bytes) */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields(s, &(message->NtChallengeResponse)) <
 	    0) /* NtChallengeResponseFields (8 bytes) */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields(s, &(message->DomainName)) < 0) /* DomainNameFields (8 bytes) */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields(s, &(message->UserName)) < 0) /* UserNameFields (8 bytes) */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields(s, &(message->Workstation)) < 0) /* WorkstationFields (8 bytes) */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields(s, &(message->EncryptedRandomSessionKey)) <
 	    0) /* EncryptedRandomSessionKeyFields (8 bytes) */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
-
+		goto fail;
+
+	if (Stream_GetRemainingLength(s) < 4)
+		goto fail;
 	Stream_Read_UINT32(s, message->NegotiateFlags); /* NegotiateFlags (4 bytes) */
 	context->NegotiateKeyExchange =
 	    (message->NegotiateFlags & NTLMSSP_NEGOTIATE_KEY_EXCH) ? TRUE : FALSE;
 
 	if ((context->NegotiateKeyExchange && !message->EncryptedRandomSessionKey.Len) ||
 	    (!context->NegotiateKeyExchange && message->EncryptedRandomSessionKey.Len))
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INVALID_TOKEN;
-	}
+		goto fail;
 
 	if (message->NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION)
 	{
 		if (ntlm_read_version_info(s, &(message->Version)) < 0) /* Version (8 bytes) */
-		{
-			Stream_Free(s, FALSE);
-			return SEC_E_INVALID_TOKEN;
-		}
+			goto fail;
 	}
 
 	PayloadBufferOffset = Stream_GetPosition(s);
 
+	status = SEC_E_INTERNAL_ERROR;
 	if (ntlm_read_message_fields_buffer(s, &(message->DomainName)) < 0) /* DomainName */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INTERNAL_ERROR;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields_buffer(s, &(message->UserName)) < 0) /* UserName */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INTERNAL_ERROR;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields_buffer(s, &(message->Workstation)) < 0) /* Workstation */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INTERNAL_ERROR;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields_buffer(s, &(message->LmChallengeResponse)) <
 	    0) /* LmChallengeResponse */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INTERNAL_ERROR;
-	}
+		goto fail;
 
 	if (ntlm_read_message_fields_buffer(s, &(message->NtChallengeResponse)) <
 	    0) /* NtChallengeResponse */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INTERNAL_ERROR;
-	}
+		goto fail;
 
 	if (message->NtChallengeResponse.Len > 0)
 	{
+		int rc;
 		size_t cbAvFlags;
 		wStream* snt =
 		    Stream_New(message->NtChallengeResponse.Buffer, message->NtChallengeResponse.Len);
 
 		if (!snt)
-		{
-			Stream_Free(s, FALSE);
-			return SEC_E_INTERNAL_ERROR;
-		}
-
-		if (ntlm_read_ntlm_v2_response(snt, &(context->NTLMv2Response)) < 0)
-		{
-			Stream_Free(s, FALSE);
-			Stream_Free(snt, FALSE);
-			return SEC_E_INVALID_TOKEN;
-		}
-
+			goto fail;
+
+		status = SEC_E_INVALID_TOKEN;
+		rc = ntlm_read_ntlm_v2_response(snt, &(context->NTLMv2Response));
 		Stream_Free(snt, FALSE);
+		if (rc < 0)
+			goto fail;
+		status = SEC_E_INTERNAL_ERROR;
+
 		context->NtChallengeResponse.pvBuffer = message->NtChallengeResponse.Buffer;
 		context->NtChallengeResponse.cbBuffer = message->NtChallengeResponse.Len;
 		sspi_SecBufferFree(&(context->ChallengeTargetInfo));
@@ -838,18 +793,12 @@
 
 	if (ntlm_read_message_fields_buffer(s, &(message->EncryptedRandomSessionKey)) <
 	    0) /* EncryptedRandomSessionKey */
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INTERNAL_ERROR;
-	}
+		goto fail;
 
 	if (message->EncryptedRandomSessionKey.Len > 0)
 	{
 		if (message->EncryptedRandomSessionKey.Len != 16)
-		{
-			Stream_Free(s, FALSE);
-			return SEC_E_INVALID_TOKEN;
-		}
+			goto fail;
 
 		CopyMemory(context->EncryptedRandomSessionKey, message->EncryptedRandomSessionKey.Buffer,
 		           16);
@@ -858,10 +807,7 @@
 	length = Stream_GetPosition(s);
 
 	if (!sspi_SecBufferAlloc(&context->AuthenticateMessage, length))
-	{
-		Stream_Free(s, FALSE);
-		return SEC_E_INTERNAL_ERROR;
-	}
+		goto fail;
 
 	CopyMemory(context->AuthenticateMessage.pvBuffer, Stream_Buffer(s), length);
 	buffer->cbBuffer = length;
@@ -871,14 +817,14 @@
 	{
 		context->MessageIntegrityCheckOffset = (UINT32)Stream_GetPosition(s);
 
+		status = SEC_E_INVALID_TOKEN;
 		if (Stream_GetRemainingLength(s) < 16)
-		{
-			Stream_Free(s, FALSE);
-			return SEC_E_INVALID_TOKEN;
-		}
+			goto fail;
 
 		Stream_Read(s, message->MessageIntegrityCheck, 16);
 	}
+
+	status = SEC_E_INTERNAL_ERROR;
 
 #ifdef WITH_DEBUG_NTLM
 	WLog_DBG(TAG, "AUTHENTICATE_MESSAGE (length = %" PRIu32 ")",
@@ -911,10 +857,7 @@
 		credentials->identity.User = (UINT16*)malloc(message->UserName.Len);
 
 		if (!credentials->identity.User)
-		{
-			Stream_Free(s, FALSE);
-			return SEC_E_INTERNAL_ERROR;
-		}
+			goto fail;
 
 		CopyMemory(credentials->identity.User, message->UserName.Buffer, message->UserName.Len);
 		credentials->identity.UserLength = message->UserName.Len / 2;
@@ -925,10 +868,7 @@
 		credentials->identity.Domain = (UINT16*)malloc(message->DomainName.Len);
 
 		if (!credentials->identity.Domain)
-		{
-			Stream_Free(s, FALSE);
-			return SEC_E_INTERNAL_ERROR;
-		}
+			goto fail;
 
 		CopyMemory(credentials->identity.Domain, message->DomainName.Buffer,
 		           message->DomainName.Len);
@@ -939,6 +879,10 @@
 	/* Computations beyond this point require the NTLM hash of the password */
 	context->state = NTLM_STATE_COMPLETION;
 	return SEC_I_COMPLETE_NEEDED;
+
+fail:
+	Stream_Free(s, FALSE);
+	return status;
 }
 
 /**
```
