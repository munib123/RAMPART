# CrossVul Fix Pair: Improper Certificate Validation in c
**Pair ID:** 4597_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4597_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```c
Lines 649-689 of the vulnerable file.

	unsigned int len;
	struct x509_digest *elem;
	char digest_str[SHA256STRLEN], *subject, *issuer;
	char *line;
	int i;
	X509_NAME *subj;
	char common_name[FIELD_SIZE + 1];

	SSL_set_verify(tunnel->ssl_handle, SSL_VERIFY_PEER, NULL);

	X509 *cert = SSL_get_peer_certificate(tunnel->ssl_handle);
	if (cert == NULL) {
		log_error("Unable to get gateway certificate.\n");
		return 1;
	}

	subj = X509_get_subject_name(cert);

#ifdef HAVE_X509_CHECK_HOST
	// Use OpenSSL native host validation if v >= 1.0.2.
	if (X509_check_host(cert, common_name, FIELD_SIZE, 0, NULL))
		cert_valid = 1;
#else
	// Use explicit Common Name check if native validation not available.
	// Note: this will ignore Subject Alternative Name fields.
	if (subj
	    && X509_NAME_get_text_by_NID(subj, NID_commonName, common_name,
	                                 FIELD_SIZE) > 0
	    && strncasecmp(common_name, tunnel->config->gateway_host,
	                   FIELD_SIZE) == 0)
		cert_valid = 1;
#endif

	// Try to validate certificate using local PKI
	if (cert_valid
	    && SSL_get_verify_result(tunnel->ssl_handle) == X509_V_OK) {
		log_debug("Gateway certificate validation succeeded.\n");
		ret = 0;
		goto free_cert;
	}
	log_debug("Gateway certificate validation failed.\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -666,7 +666,8 @@
 
 #ifdef HAVE_X509_CHECK_HOST
 	// Use OpenSSL native host validation if v >= 1.0.2.
-	if (X509_check_host(cert, common_name, FIELD_SIZE, 0, NULL))
+	// correctly check return value of X509_check_host
+	if (X509_check_host(cert, common_name, FIELD_SIZE, 0, NULL) == 1)
 		cert_valid = 1;
 #else
 	// Use explicit Common Name check if native validation not available.
```
