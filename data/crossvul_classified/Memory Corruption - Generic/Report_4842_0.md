# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 4842_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4842_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 50-99 of the vulnerable file.

 * GNUTLS 1.X.X defined LIBGNUTLS_VERSION_NUMBER so treat it as "old" gnutls as
 * well
 */
#if (defined(GNUTLS_VERSION_NUMBER) && GNUTLS_VERSION_NUMBER < 0x020606) || \
    defined(LIBGNUTLS_VERSION_NUMBER)
#define WITHOUT_X509_TIMES
#endif

/* Ancient GNUTLS... */
#if !defined(GNUTLS_VERSION_NUMBER) && !defined(LIBGNUTLS_VERSION_NUMBER)
#define WITHOUT_X509_TIMES
#endif

using namespace rfb;

StringParameter CSecurityTLS::X509CA("X509CA", "X509 CA certificate", "", ConfViewer);
StringParameter CSecurityTLS::X509CRL("X509CRL", "X509 CRL file", "", ConfViewer);

static LogWriter vlog("TLS");

void CSecurityTLS::initGlobal()
{
  static bool globalInitDone = false;

  if (!globalInitDone) {
    gnutls_global_init();
    globalInitDone = true;
  }
}

CSecurityTLS::CSecurityTLS(bool _anon) : session(0), anon_cred(0),
						 anon(_anon), fis(0), fos(0)
{
  cafile = X509CA.getData();
  crlfile = X509CRL.getData();
}

void CSecurityTLS::setDefaults()
{
  char* homeDir = NULL;

  if (getvnchomedir(&homeDir) == -1) {
    vlog.error("Could not obtain VNC home directory path");
    return;
  }

  int len = strlen(homeDir) + 1;
  CharArray caDefault(len + 11);
  CharArray crlDefault(len + 12);
  sprintf(caDefault.buf, "%sx509_ca.pem", homeDir);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,21 +67,14 @@
 
 static LogWriter vlog("TLS");
 
-void CSecurityTLS::initGlobal()
-{
-  static bool globalInitDone = false;
-
-  if (!globalInitDone) {
-    gnutls_global_init();
-    globalInitDone = true;
-  }
-}
-
 CSecurityTLS::CSecurityTLS(bool _anon) : session(0), anon_cred(0),
 						 anon(_anon), fis(0), fos(0)
 {
   cafile = X509CA.getData();
   crlfile = X509CRL.getData();
+
+  if (gnutls_global_init() != GNUTLS_E_SUCCESS)
+    throw AuthFailureException("gnutls_global_init failed");
 }
 
 void CSecurityTLS::setDefaults()
@@ -125,8 +118,6 @@
   if (session) {
     gnutls_deinit(session);
     session = 0;
-
-    gnutls_global_deinit();
   }
 }
 
@@ -142,6 +133,8 @@
 
   delete[] cafile;
   delete[] crlfile;
+
+  gnutls_global_deinit();
 }
 
 bool CSecurityTLS::processMsg(CConnection* cc)
@@ -149,8 +142,6 @@
   rdr::InStream* is = cc->getInStream();
   rdr::OutStream* os = cc->getOutStream();
   client = cc;
-
-  initGlobal();
 
   if (!session) {
     if (!is->checkNoWait(1))
```
