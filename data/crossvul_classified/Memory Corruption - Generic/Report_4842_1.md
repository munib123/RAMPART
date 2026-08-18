# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4842_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4842_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 45-78 of the vulnerable file.

    CSecurityTLS(bool _anon);
    virtual ~CSecurityTLS();
    virtual bool processMsg(CConnection* cc);
    virtual int getType() const { return anon ? secTypeTLSNone : secTypeX509None; }
    virtual const char* description() const
      { return anon ? "TLS Encryption without VncAuth" : "X509 Encryption without VncAuth"; }
    static void setDefaults();

    static StringParameter X509CA;
    static StringParameter X509CRL;
    static UserMsgBox *msg;

  protected:
    void shutdown(bool needbye);
    void freeResources();
    void setParam();
    void checkSession();
    CConnection *client;

  private:
    static void initGlobal();

    gnutls_session_t session;
    gnutls_anon_client_credentials_t anon_cred;
    gnutls_certificate_credentials_t cert_cred;
    bool anon;

    char *cafile, *crlfile;
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
@@ -62,8 +62,6 @@
     CConnection *client;
 
   private:
-    static void initGlobal();
-
     gnutls_session_t session;
     gnutls_anon_client_credentials_t anon_cred;
     gnutls_certificate_credentials_t cert_cred;
```
