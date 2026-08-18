# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 512_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `512_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 253-293 of the vulnerable file.

#define SCRIPT_AMBIGUOUS_SLASH_IN_PATH 729
#define CERT_IP_CANNOT_VERIFY   730
#define HOSTKEY_NOT_CONFIGURED  731
#define UNENCRYPTED_REDIRECT    732
#define HTTP_ERROR2             733
#define FILEZILLA_SITE_MANAGER_NOT_FOUND 734
#define FILEZILLA_NO_SITES      735
#define FILEZILLA_SITE_NOT_EXIST 736
#define SFTP_AS_FTP_ERROR       737
#define LOG_FATAL_ERROR         738
#define SIZE_INVALID            739
#define KNOWN_HOSTS_NOT_FOUND   740
#define KNOWN_HOSTS_NO_SITES    741
#define HOSTKEY_NOT_MATCH_CLIPBOARD 742
#define S3_ERROR_RESOURCE       743
#define S3_ERROR_FURTHER_DETAILS 744
#define S3_ERROR_EXTRA_DETAILS  745
#define S3_STATUS_ACCESS_DENIED 746
#define UNKNOWN_FILE_ENCRYPTION 747
#define INVALID_ENCRYPT_KEY     748

#define CORE_CONFIRMATION_STRINGS 300
#define CONFIRM_PROLONG_TIMEOUT3 301
#define PROMPT_KEY_PASSPHRASE   303
#define FILE_OVERWRITE          304
#define DIRECTORY_OVERWRITE     305
#define ALG_BELOW_TRESHOLD      306
#define CIPHER_TYPE_BOTH2       307
#define CIPHER_TYPE_CS2         308
#define CIPHER_TYPE_SC2         309
#define RESUME_TRANSFER2        310
#define PARTIAL_BIGGER_THAN_SOURCE 311
#define APPEND_OR_RESUME2       312
#define FILE_OVERWRITE_DETAILS  313
#define READ_ONLY_OVERWRITE     314
#define LOCAL_FILE_OVERWRITE2   315
#define REMOTE_FILE_OVERWRITE2  316
#define TIMEOUT_STILL_WAITING3  321
#define RECONNECT_BUTTON        323
#define RENAME_BUTTON           324
#define TUNNEL_SESSION_NAME     327
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -270,6 +270,7 @@
 #define S3_STATUS_ACCESS_DENIED 746
 #define UNKNOWN_FILE_ENCRYPTION 747
 #define INVALID_ENCRYPT_KEY     748
+#define UNREQUESTED_FILE        749
 
 #define CORE_CONFIRMATION_STRINGS 300
 #define CONFIRM_PROLONG_TIMEOUT3 301
```
