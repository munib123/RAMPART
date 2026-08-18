# CrossVul Fix Pair: Improper Certificate Validation in c
**Pair ID:** 1607_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1607_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```c
Lines 692-732 of the vulnerable file.

       * does not tell us whether the certificate is otherwise invalid
       * if a signer is not found already. */
      /* TODO: Here it would be good to use the verify flags from the
       * certificate credentials, but GnuTLS does not have API to
       * retrieve them. */
      root_cert = inf_certificate_chain_get_root_certificate(chain);

      ret = gnutls_x509_crt_list_verify(
        inf_certificate_chain_get_raw(chain),
        inf_certificate_chain_get_n_certificates(chain),
        &root_cert,
        1,
        NULL,
        0,
        GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
        &verify
      );

      if(ret != GNUTLS_E_SUCCESS)
        inf_gnutls_set_error(&error, ret);
      else if(verify & GNUTLS_CERT_INVALID)
        inf_gnutls_certificate_verification_set_error(&error, verify);
    }
  }

  /* Look up the host in our database of pinned certificates if we could not
   * fully verify the certificate, i.e. if either the issuer is not known or
   * the hostname of the connection does not match the certificate. */
  table = NULL;
  if(error == NULL)
  {
    known_cert = NULL;
    if(!match_hostname || !issuer_known)
    {
      /* If we cannot load the known host file, then cancel the connection.
       * Otherwise it might happen that someone shows us a certificate that we
       * tell the user we don't know, if though actually for that host we expect
       * a different certificate. */
      table = inf_gtk_certificate_manager_ref_known_hosts(manager, &error);
      if(table != NULL)
        known_cert = g_hash_table_lookup(table, hostname);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -709,9 +709,11 @@
 
       if(ret != GNUTLS_E_SUCCESS)
         inf_gnutls_set_error(&error, ret);
-      else if(verify & GNUTLS_CERT_INVALID)
+    }
+
+    if(error == NULL)
+      if(verify & GNUTLS_CERT_INVALID)
         inf_gnutls_certificate_verification_set_error(&error, verify);
-    }
   }
 
   /* Look up the host in our database of pinned certificates if we could not
```
