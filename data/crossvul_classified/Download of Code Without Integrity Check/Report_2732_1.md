# CrossVul Fix Pair: Download of Code Without Integrity Check in c
**Pair ID:** 2732_1
**Vulnerability Class:** Download of Code Without Integrity Check
**CWE:** CWE-494
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2732_1`)

## Vulnerability Information & PoC

## Description
Download of Code Without Integrity Check - An attacker can execute malicious code by compromising the host server, performing DNS spoofing, or modifying the code in transit.

## Vulnerable Code
```c
Lines 36-76 of the vulnerable file.

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

// Signatures names we accept (may be suffixed, but the signature should start with one of those)
const char* cert_name[3] = { "Akeo Consulting", "Akeo Systems", "Pete Batard" };

typedef struct {
	LPWSTR lpszProgramName;
	LPWSTR lpszPublisherLink;
	LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, *PSPROG_PUBLISHERINFO;


/*
 * FormatMessage does not handle PKI errors
 */
const char* WinPKIErrorString(void)
{
	static char error_string[64];
	DWORD error_code = GetLastError();

	if ((error_code >> 16) != 0x8009)
		return WindowsErrorString();

	switch (error_code) {
	case NTE_BAD_UID:
		return "Bad UID.";
	case CRYPT_E_MSG_ERROR:
		return "An error occurred while performing an operation on a cryptographic message.";
	case CRYPT_E_UNKNOWN_ALGO:
		return "Unknown cryptographic algorithm.";
	case CRYPT_E_INVALID_MSG_TYPE:
		return "Invalid cryptographic message type.";
	case CRYPT_E_HASH_VALUE:
		return "The hash value is not correct";
	case CRYPT_E_ISSUER_SERIALNUMBER:
		return "Invalid issuer and/or serial number.";
	case CRYPT_E_BAD_LEN:
		return "The length specified for the output data was insufficient.";
	case CRYPT_E_BAD_ENCODE:
		return "An error occurred during encode or decode operation.";
	case CRYPT_E_FILE_ERROR:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
 	static char error_string[64];
 	DWORD error_code = GetLastError();
 
-	if ((error_code >> 16) != 0x8009)
+	if (((error_code >> 16) != 0x8009) && ((error_code >> 16) != 0x800B))
 		return WindowsErrorString();
 
 	switch (error_code) {
@@ -113,6 +113,12 @@
 		return "Cannot complete usage check.";
 	case CRYPT_E_NO_TRUSTED_SIGNER:
 		return "None of the signers of the cryptographic message or certificate trust list is trusted.";
+	case CERT_E_UNTRUSTEDROOT:
+		return "The root certificate is not trusted.";
+	case TRUST_E_NOSIGNATURE:
+		return "Not digitally signed.";
+	case TRUST_E_EXPLICIT_DISTRUST:
+		return "One of the certificates used was marked as untrusted by the user.";
 	default:
 		static_sprintf(error_string, "Unknown PKI error 0x%08lX", error_code);
 		return error_string;
@@ -268,7 +274,13 @@
 	}
 
 	trust_data.cbStruct = sizeof(trust_data);
-	trust_data.dwUIChoice = WTD_UI_ALL;
+	// NB: WTD_UI_ALL can result in ERROR_SUCCESS even if the signature validation fails,
+	// because it still prompts the user to run untrusted software, even after explicitly
+	// notifying them that the signature invalid (and of course Microsoft had to make
+	// that UI prompt a bit too similar to the other benign prompt you get when running
+	// trusted software, which, as per cert.org's assessment, may confuse non-security
+	// conscious-users who decide to gloss over these kind of notifications).
+	trust_data.dwUIChoice = WTD_UI_NONE;
 	// We just downloaded from the Internet, so we should be able to check revocation
 	trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
 	// 0x400 = WTD_MOTW  for Windows 8.1 or later
@@ -278,6 +290,19 @@
 
 	r = WinVerifyTrust(NULL, &guid_generic_verify, &trust_data);
 	safe_free(trust_file.pcwszFilePath);
+	switch (r) {
+	case ERROR_SUCCESS:
+		break;
+	case TRUST_E_NOSIGNATURE:
+		// Should already have been reported, but since we have a custom message for it...
+		uprintf("PKI: File does not appear to be signed: %s", WinPKIErrorString());
+		MessageBoxExU(hDlg, lmprintf(MSG_284), lmprintf(MSG_283), MB_OK | MB_ICONERROR | MB_IS_RTL, selected_langid);
+		break;
+	default:
+		uprintf("PKI: Failed to validate signature: %s", WinPKIErrorString());
+		MessageBoxExU(hDlg, lmprintf(MSG_240), lmprintf(MSG_283), MB_OK | MB_ICONERROR | MB_IS_RTL, selected_langid);
+		break;
+	}
 
 	return r;
 }
```
