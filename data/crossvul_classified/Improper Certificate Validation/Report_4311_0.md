# CrossVul Fix Pair: Improper Certificate Validation in cpp
**Pair ID:** 4311_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4311_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```cpp
Lines 233-288 of the vulnerable file.

  }

  if (anon) {
    if (gnutls_anon_allocate_client_credentials(&anon_cred) != GNUTLS_E_SUCCESS)
      throw AuthFailureException("gnutls_anon_allocate_client_credentials failed");

    if (gnutls_credentials_set(session, GNUTLS_CRD_ANON, anon_cred) != GNUTLS_E_SUCCESS)
      throw AuthFailureException("gnutls_credentials_set failed");

    vlog.debug("Anonymous session has been set");
  } else {
    if (gnutls_certificate_allocate_credentials(&cert_cred) != GNUTLS_E_SUCCESS)
      throw AuthFailureException("gnutls_certificate_allocate_credentials failed");

    if (gnutls_certificate_set_x509_system_trust(cert_cred) != GNUTLS_E_SUCCESS)
      vlog.error("Could not load system certificate trust store");

    if (*cafile && gnutls_certificate_set_x509_trust_file(cert_cred,cafile,GNUTLS_X509_FMT_PEM) < 0)
      throw AuthFailureException("load of CA cert failed");

    /* Load previously saved certs */
    char *homeDir = NULL;
    int err;
    if (getvnchomedir(&homeDir) == -1)
      vlog.error("Could not obtain VNC home directory path");
    else {
      CharArray caSave(strlen(homeDir) + 19 + 1);
      sprintf(caSave.buf, "%sx509_savedcerts.pem", homeDir);
      delete [] homeDir;

      err = gnutls_certificate_set_x509_trust_file(cert_cred, caSave.buf,
                                                   GNUTLS_X509_FMT_PEM);
      if (err < 0)
        vlog.debug("Failed to load saved server certificates from %s", caSave.buf);
    }

    if (*crlfile && gnutls_certificate_set_x509_crl_file(cert_cred,crlfile,GNUTLS_X509_FMT_PEM) < 0)
      throw AuthFailureException("load of CRL failed");

    if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cert_cred) != GNUTLS_E_SUCCESS)
      throw AuthFailureException("gnutls_credentials_set failed");

    if (gnutls_server_name_set(session, GNUTLS_NAME_DNS,
                               client->getServerName(),
                               strlen(client->getServerName())) != GNUTLS_E_SUCCESS)
      vlog.error("Failed to configure the server name for TLS handshake");

    vlog.debug("X509 session has been set");
  }
}

void CSecurityTLS::checkSession()
{
  const unsigned allowed_errors = GNUTLS_CERT_INVALID |
				  GNUTLS_CERT_SIGNER_NOT_FOUND |
				  GNUTLS_CERT_SIGNER_NOT_CA;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -250,22 +250,6 @@
     if (*cafile && gnutls_certificate_set_x509_trust_file(cert_cred,cafile,GNUTLS_X509_FMT_PEM) < 0)
       throw AuthFailureException("load of CA cert failed");
 
-    /* Load previously saved certs */
-    char *homeDir = NULL;
-    int err;
-    if (getvnchomedir(&homeDir) == -1)
-      vlog.error("Could not obtain VNC home directory path");
-    else {
-      CharArray caSave(strlen(homeDir) + 19 + 1);
-      sprintf(caSave.buf, "%sx509_savedcerts.pem", homeDir);
-      delete [] homeDir;
-
-      err = gnutls_certificate_set_x509_trust_file(cert_cred, caSave.buf,
-                                                   GNUTLS_X509_FMT_PEM);
-      if (err < 0)
-        vlog.debug("Failed to load saved server certificates from %s", caSave.buf);
-    }
-
     if (*crlfile && gnutls_certificate_set_x509_crl_file(cert_cred,crlfile,GNUTLS_X509_FMT_PEM) < 0)
       throw AuthFailureException("load of CRL failed");
 
@@ -290,7 +274,10 @@
   const gnutls_datum_t *cert_list;
   unsigned int cert_list_size = 0;
   int err;
+
+  char *homeDir;
   gnutls_datum_t info;
+  size_t len;
 
   if (anon)
     return;
@@ -333,13 +320,13 @@
     throw AuthFailureException("decoding of certificate failed");
 
   if (gnutls_x509_crt_check_hostname(crt, client->getServerName()) == 0) {
-    char buf[255];
+    CharArray text;
     vlog.debug("hostname mismatch");
-    snprintf(buf, sizeof(buf), "Hostname (%s) does not match any certificate, "
-			       "do you want to continue?", client->getServerName());
-    buf[sizeof(buf) - 1] = '\0';
-    if (!msg->showMsgBox(UserMsgBox::M_YESNO, "hostname mismatch", buf))
-      throw AuthFailureException("hostname mismatch");
+    text.format("Hostname (%s) does not match the server certificate, "
+                "do you want to continue?", client->getServerName());
+    if (!msg->showMsgBox(UserMsgBox::M_YESNO,
+                         "Certificate hostname mismatch", text.buf))
+      throw AuthFailureException("Certificate hostname mismatch");
   }
 
   if (status == 0) {
@@ -364,86 +351,82 @@
     throw AuthFailureException("Invalid status of server certificate verification");
   }
 
-  vlog.debug("Saved server certificates don't match");
-
-  if (gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_ONELINE, &info)) {
-    /*
-     * GNUTLS doesn't correctly export gnutls_free symbol which is
-     * a function pointer. Linking with Visual Studio 2008 Express will
-     * fail when you call gnutls_free().
-     */
-#if WIN32
-    free(info.data);
-#else
-    gnutls_free(info.data);
-#endif
+  /* Certificate is fine, except we don't know the issuer, so TOFU time */
+
+  homeDir = NULL;
+  if (getvnchomedir(&homeDir) == -1) {
+    throw AuthFailureException("Could not obtain VNC home directory "
+                               "path for known hosts storage");
+  }
+
+  CharArray dbPath(strlen(homeDir) + 16 + 1);
+  sprintf(dbPath.buf, "%sx509_known_hosts", homeDir);
+  delete [] homeDir;
+
+  err = gnutls_verify_stored_pubkey(dbPath.buf, NULL,
+                                    client->getServerName(), NULL,
+                                    GNUTLS_CRT_X509, &cert_list[0], 0);
+
+  /* Previously known? */
+  if (err == GNUTLS_E_SUCCESS) {
+    vlog.debug("Server certificate found in known hosts file");
+    gnutls_x509_crt_deinit(crt);
+    return;
+  }
+
+  if ((err != GNUTLS_E_NO_CERTIFICATE_FOUND) &&
+      (err != GNUTLS_E_CERTIFICATE_KEY_MISMATCH)) {
+    throw AuthFailureException("Could not load known hosts database");
+  }
+
+  if (gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_ONELINE, &info))
     throw AuthFailureException("Could not find certificate to display");
-  }
-
-  size_t out_size = 0;
-  char *out_buf = NULL;
-  char *certinfo = NULL;
-  int len = 0;
-
-  vlog.debug("certificate issuer unknown");
-
-  len = snprintf(NULL, 0, "This certificate has been signed by an unknown "
-                          "authority:\n\n%s\n\nDo you want to save it and "
-                          "continue?\n ", info.data);
-  if (len < 0)
-    throw AuthFailureException("certificate decoding error");
-
-  vlog.debug("%s", info.data);
-
-  certinfo = new char[len];
-
-  snprintf(certinfo, len, "This certificate has been signed by an unknown "
-                          "authority:\n\n%s\n\nDo you want to save it and "
-                          "continue? ", info.data);
-
-  for (int i = 0; i < len - 1; i++)
-    if (certinfo[i] == ',' && certinfo[i + 1] == ' ')
-      certinfo[i] = '\n';
-
-  if (!msg->showMsgBox(UserMsgBox::M_YESNO, "certificate issuer unknown",
-		       certinfo)) {
-    delete [] certinfo;
-    throw AuthFailureException("certificate issuer unknown");
-  }
-
-  delete [] certinfo;
-
-  if (gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM, NULL, &out_size)
-      != GNUTLS_E_SHORT_MEMORY_BUFFER)
-    throw AuthFailureException("certificate issuer unknown, and certificate "
-                               "export failed");
-
-  // Save cert
-  out_buf =  new char[out_size];
-
-  if (gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM, out_buf, &out_size) < 0)
-    throw AuthFailureException("certificate issuer unknown, and certificate "
-                               "export failed");
-
-  char *homeDir = NULL;
-  if (getvnchomedir(&homeDir) == -1)
-    vlog.error("Could not obtain VNC home directory path");
-  else {
-    FILE *f;
-    CharArray caSave(strlen(homeDir) + 1 + 19);
-    sprintf(caSave.buf, "%sx509_savedcerts.pem", homeDir);
-    delete [] homeDir;
-    f = fopen(caSave.buf, "a+");
-    if (!f)
-      msg->showMsgBox(UserMsgBox::M_OK, "certificate save failed",
-                      "Could not save the certificate");
-    else {
-      fprintf(f, "%s\n", out_buf);
-      fclose(f);
-    }
-  }
-
-  delete [] out_buf;
+
+  len = strlen((char*)info.data);
+  for (size_t i = 0; i < len - 1; i++) {
+    if (info.data[i] == ',' && info.data[i + 1] == ' ')
+      info.data[i] = '\n';
+  }
+
+  /* New host */
+  if (err == GNUTLS_E_NO_CERTIFICATE_FOUND) {
+    CharArray text;
+
+    vlog.debug("Server host not previously known");
+    vlog.debug("%s", info.data);
+
+    text.format("This certificate has been signed by an unknown "
+                "authority:\n\n%s\n\nSomeone could be trying to "
+                "impersonate the site and you should not "
+                "continue.\n\nDo you want to make an exception "
+                "for this server?", info.data);
+
+    if (!msg->showMsgBox(UserMsgBox::M_YESNO,
+                         "Unknown certificate issuer",
+                         text.buf))
+      throw AuthFailureException("Unknown certificate issuer");
+  } else if (err == GNUTLS_E_CERTIFICATE_KEY_MISMATCH) {
+    CharArray text;
+
+    vlog.debug("Server host key mismatch");
+    vlog.debug("%s", info.data);
+
+    text.format("This host is previously known with a different "
+                "certificate, and the new certificate has been "
+                "signed by an unknown authority:\n\n%s\n\nSomeone "
+                "could be trying to impersonate the site and you "
+                "should not continue.\n\nDo you want to make an "
+                "exception for this server?", info.data);
+
+    if (!msg->showMsgBox(UserMsgBox::M_YESNO,
+                         "Unexpected server certificate",
+                         text.buf))
+      throw AuthFailureException("Unexpected server certificate");
+  }
+
+  if (gnutls_store_pubkey(dbPath.buf, NULL, client->getServerName(),
+                          NULL, GNUTLS_CRT_X509, &cert_list[0], 0, 0))
+    vlog.error("Failed to store server certificate to known hosts database");
 
   gnutls_x509_crt_deinit(crt);
   /*
```
