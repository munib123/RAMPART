# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 4842_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4842_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 31-81 of the vulnerable file.


#include <rfb/SSecurityTLS.h>
#include <rfb/SConnection.h>
#include <rfb/LogWriter.h>
#include <rfb/Exception.h>
#include <rdr/TLSInStream.h>
#include <rdr/TLSOutStream.h>

#define DH_BITS 1024 /* XXX This should be configurable! */

using namespace rfb;

StringParameter SSecurityTLS::X509_CertFile
("X509Cert", "Path to the X509 certificate in PEM format", "", ConfServer);

StringParameter SSecurityTLS::X509_KeyFile
("X509Key", "Path to the key of the X509 certificate in PEM format", "", ConfServer);

static LogWriter vlog("TLS");

void SSecurityTLS::initGlobal()
{
  static bool globalInitDone = false;

  if (!globalInitDone) {
    if (gnutls_global_init() != GNUTLS_E_SUCCESS)
      throw AuthFailureException("gnutls_global_init failed");
    globalInitDone = true;
  }
}

SSecurityTLS::SSecurityTLS(bool _anon) : session(0), dh_params(0),
						 anon_cred(0), cert_cred(0),
						 anon(_anon), fis(0), fos(0)
{
  certfile = X509_CertFile.getData();
  keyfile = X509_KeyFile.getData();
}

void SSecurityTLS::shutdown()
{
  if (session) {
    if (gnutls_bye(session, GNUTLS_SHUT_RDWR) != GNUTLS_E_SUCCESS) {
      /* FIXME: Treat as non-fatal error */
      vlog.error("TLS session wasn't terminated gracefully");
    }
  }

  if (dh_params) {
    gnutls_dh_params_deinit(dh_params);
    dh_params = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -48,23 +48,15 @@
 
 static LogWriter vlog("TLS");
 
-void SSecurityTLS::initGlobal()
-{
-  static bool globalInitDone = false;
-
-  if (!globalInitDone) {
-    if (gnutls_global_init() != GNUTLS_E_SUCCESS)
-      throw AuthFailureException("gnutls_global_init failed");
-    globalInitDone = true;
-  }
-}
-
 SSecurityTLS::SSecurityTLS(bool _anon) : session(0), dh_params(0),
 						 anon_cred(0), cert_cred(0),
 						 anon(_anon), fis(0), fos(0)
 {
   certfile = X509_CertFile.getData();
   keyfile = X509_KeyFile.getData();
+
+  if (gnutls_global_init() != GNUTLS_E_SUCCESS)
+    throw AuthFailureException("gnutls_global_init failed");
 }
 
 void SSecurityTLS::shutdown()
@@ -94,8 +86,6 @@
   if (session) {
     gnutls_deinit(session);
     session = 0;
-
-    gnutls_global_deinit();
   }
 }
 
@@ -111,6 +101,8 @@
 
   delete[] keyfile;
   delete[] certfile;
+
+  gnutls_global_deinit();
 }
 
 bool SSecurityTLS::processMsg(SConnection *sc)
@@ -121,8 +113,6 @@
   vlog.debug("Process security message (session %p)", session);
 
   if (!session) {
-    initGlobal();
-
     if (gnutls_init(&session, GNUTLS_SERVER) != GNUTLS_E_SUCCESS)
       throw AuthFailureException("gnutls_init failed");
 
```
