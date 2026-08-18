# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 101_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `101_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 327-368 of the vulnerable file.

	return 0;
}

/* BB Move to ntlmssp.c eventually */

/* We do not malloc the blob, it is passed in pbuffer, because
   it is fixed size, and small, making this approach cleaner */
void build_ntlmssp_negotiate_blob(unsigned char *pbuffer,
					 struct cifs_ses *ses)
{
	NEGOTIATE_MESSAGE *sec_blob = (NEGOTIATE_MESSAGE *)pbuffer;
	__u32 flags;

	memset(pbuffer, 0, sizeof(NEGOTIATE_MESSAGE));
	memcpy(sec_blob->Signature, NTLMSSP_SIGNATURE, 8);
	sec_blob->MessageType = NtLmNegotiate;

	/* BB is NTLMV2 session security format easier to use here? */
	flags = NTLMSSP_NEGOTIATE_56 |	NTLMSSP_REQUEST_TARGET |
		NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_UNICODE |
		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SEC;
	if (ses->server->sign) {
		flags |= NTLMSSP_NEGOTIATE_SIGN;
		if (!ses->server->session_estab ||
				ses->ntlmssp->sesskey_per_smbsess)
			flags |= NTLMSSP_NEGOTIATE_KEY_XCH;
	}

	sec_blob->NegotiateFlags = cpu_to_le32(flags);

	sec_blob->WorkstationName.BufferOffset = 0;
	sec_blob->WorkstationName.Length = 0;
	sec_blob->WorkstationName.MaximumLength = 0;

	/* Domain name is sent on the Challenge not Negotiate NTLMSSP request */
	sec_blob->DomainName.BufferOffset = 0;
	sec_blob->DomainName.Length = 0;
	sec_blob->DomainName.MaximumLength = 0;
}

static int size_of_ntlmssp_blob(struct cifs_ses *ses)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -344,13 +344,12 @@
 	/* BB is NTLMV2 session security format easier to use here? */
 	flags = NTLMSSP_NEGOTIATE_56 |	NTLMSSP_REQUEST_TARGET |
 		NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_UNICODE |
-		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SEC;
-	if (ses->server->sign) {
+		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SEC |
+		NTLMSSP_NEGOTIATE_SEAL;
+	if (ses->server->sign)
 		flags |= NTLMSSP_NEGOTIATE_SIGN;
-		if (!ses->server->session_estab ||
-				ses->ntlmssp->sesskey_per_smbsess)
-			flags |= NTLMSSP_NEGOTIATE_KEY_XCH;
-	}
+	if (!ses->server->session_estab || ses->ntlmssp->sesskey_per_smbsess)
+		flags |= NTLMSSP_NEGOTIATE_KEY_XCH;
 
 	sec_blob->NegotiateFlags = cpu_to_le32(flags);
 
@@ -407,13 +406,12 @@
 	flags = NTLMSSP_NEGOTIATE_56 |
 		NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_TARGET_INFO |
 		NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_UNICODE |
-		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SEC;
-	if (ses->server->sign) {
+		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SEC |
+		NTLMSSP_NEGOTIATE_SEAL;
+	if (ses->server->sign)
 		flags |= NTLMSSP_NEGOTIATE_SIGN;
-		if (!ses->server->session_estab ||
-				ses->ntlmssp->sesskey_per_smbsess)
-			flags |= NTLMSSP_NEGOTIATE_KEY_XCH;
-	}
+	if (!ses->server->session_estab || ses->ntlmssp->sesskey_per_smbsess)
+		flags |= NTLMSSP_NEGOTIATE_KEY_XCH;
 
 	tmp = *pbuffer + sizeof(AUTHENTICATE_MESSAGE);
 	sec_blob->NegotiateFlags = cpu_to_le32(flags);
```
