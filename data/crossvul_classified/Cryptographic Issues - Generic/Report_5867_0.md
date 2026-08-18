# CrossVul Fix Pair: Cryptographic Issues in c
**Pair ID:** 5867_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5867_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```c
Lines 706-746 of the vulnerable file.

		{
			snprintf (buf, sizeof (buf), " * No Certificate");
			EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL,
							 NULL, 0);
		}

		chiper_info = _SSL_get_cipher_info (serv->ssl);	/* static buffer */
		snprintf (buf, sizeof (buf), "* Cipher info:");
		EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL, NULL,
						 0);
		snprintf (buf, sizeof (buf), "  Version: %s, cipher %s (%u bits)",
					 chiper_info->version, chiper_info->chiper,
					 chiper_info->chiper_bits);
		EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL, NULL,
						 0);

		verify_error = SSL_get_verify_result (serv->ssl);
		switch (verify_error)
		{
		case X509_V_OK:
			/* snprintf (buf, sizeof (buf), "* Verify OK (?)"); */
			/* EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL, NULL, 0); */
			break;
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		case X509_V_ERR_CERT_HAS_EXPIRED:
			if (serv->accept_invalid_cert)
			{
				snprintf (buf, sizeof (buf), "* Verify E: %s.? (%d) -- Ignored",
							 X509_verify_cert_error_string (verify_error),
							 verify_error);
				EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL,
								 NULL, 0);
				break;
			}
		default:
			snprintf (buf, sizeof (buf), "%s.? (%d)",
						 X509_verify_cert_error_string (verify_error),
						 verify_error);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -723,9 +723,22 @@
 		switch (verify_error)
 		{
 		case X509_V_OK:
+			{
+				X509 *cert = SSL_get_peer_certificate (serv->ssl);
+				int hostname_err;
+				if ((hostname_err = _SSL_check_hostname(cert, serv->hostname)) != 0)
+				{
+					snprintf (buf, sizeof (buf), "* Verify E: Failed to validate hostname? (%d)%s",
+							 hostname_err, serv->accept_invalid_cert ? " -- Ignored" : "");
+					if (serv->accept_invalid_cert)
+						EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL, NULL, 0);
+					else
+						goto conn_fail;
+				}
+				break;
+			}
 			/* snprintf (buf, sizeof (buf), "* Verify OK (?)"); */
 			/* EMIT_SIGNAL (XP_TE_SSLMESSAGE, serv->server_session, buf, NULL, NULL, NULL, 0); */
-			break;
 		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
 		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
 		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
@@ -744,6 +757,7 @@
 			snprintf (buf, sizeof (buf), "%s.? (%d)",
 						 X509_verify_cert_error_string (verify_error),
 						 verify_error);
+conn_fail:
 			EMIT_SIGNAL (XP_TE_CONNFAIL, serv->server_session, buf, NULL, NULL,
 							 NULL, 0);
 
```
