# CrossVul Fix Pair: Improper Certificate Validation in c
**Pair ID:** 4599_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4599_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```c
Lines 635-675 of the vulnerable file.

err_proxy_response:
err_connect:
	free(env_proxy); // release memory allocated by strdup()
err_strdup:
	close(handle);
err_socket:
	return -1;
}

static int ssl_verify_cert(struct tunnel *tunnel)
{
	int ret = -1;
	int cert_valid = 0;
	unsigned char digest[SHA256LEN];
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
	// correctly check return value of X509_check_host
	if (X509_check_host(cert, common_name, FIELD_SIZE, 0, NULL) == 1)
		cert_valid = 1;
#else
	// Use explicit Common Name check if native validation not available.
	// Note: this will ignore Subject Alternative Name fields.
	if (subj
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -652,7 +652,6 @@
 	char *line;
 	int i;
 	X509_NAME *subj;
-	char common_name[FIELD_SIZE + 1];
 
 	SSL_set_verify(tunnel->ssl_handle, SSL_VERIFY_PEER, NULL);
 
@@ -666,10 +665,13 @@
 
 #ifdef HAVE_X509_CHECK_HOST
 	// Use OpenSSL native host validation if v >= 1.0.2.
-	// correctly check return value of X509_check_host
-	if (X509_check_host(cert, common_name, FIELD_SIZE, 0, NULL) == 1)
+	// compare against gateway_host and correctly check return value
+	// to fix piror Incorrect use of X509_check_host
+	if (X509_check_host(cert, tunnel->config->gateway_host,
+	                    0, 0, NULL) == 1)
 		cert_valid = 1;
 #else
+	char common_name[FIELD_SIZE + 1];
 	// Use explicit Common Name check if native validation not available.
 	// Note: this will ignore Subject Alternative Name fields.
 	if (subj
```
