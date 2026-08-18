# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4842_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4842_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 37-74 of the vulnerable file.

#include <gnutls/gnutls.h>

namespace rfb {

  class SSecurityTLS : public SSecurity {
  public:
    SSecurityTLS(bool _anon);
    virtual ~SSecurityTLS();
    virtual bool processMsg(SConnection* sc);
    virtual const char* getUserName() const {return 0;}
    virtual int getType() const { return anon ? secTypeTLSNone : secTypeX509None;}

    static StringParameter X509_CertFile;
    static StringParameter X509_KeyFile;

  protected:
    void shutdown();
    void setParams(gnutls_session_t session);

  private:
    static void initGlobal();

    gnutls_session_t session;
    gnutls_dh_params_t dh_params;
    gnutls_anon_server_credentials_t anon_cred;
    gnutls_certificate_credentials_t cert_cred;
    char *keyfile, *certfile;

    int type;
    bool anon;

    rdr::InStream* fis;
    rdr::OutStream* fos;
  };

}

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,8 +54,6 @@
     void setParams(gnutls_session_t session);
 
   private:
-    static void initGlobal();
-
     gnutls_session_t session;
     gnutls_dh_params_t dh_params;
     gnutls_anon_server_credentials_t anon_cred;
```
