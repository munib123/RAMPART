# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2441_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2441_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 35-75 of the vulnerable file.

    krb5_error krberror;
    int numresult;
    char strresult[1024];
    char *clientstr = NULL, *targetstr = NULL;
    const char *errmsg = NULL;
    size_t clen;
    char *cdots;
    struct sockaddr_storage ss;
    socklen_t salen;
    char addrbuf[100];
    krb5_address *addr = remote_faddr->address;

    *rep = empty_data();

    if (req->length < 4) {
        /* either this, or the server is printing bad messages,
           or the caller passed in garbage */
        ret = KRB5KRB_AP_ERR_MODIFIED;
        numresult = KRB5_KPASSWD_MALFORMED;
        strlcpy(strresult, "Request was truncated", sizeof(strresult));
        goto chpwfail;
    }

    ptr = req->data;

    /* verify length */

    plen = (*ptr++ & 0xff);
    plen = (plen<<8) | (*ptr++ & 0xff);

    if (plen != req->length) {
        ret = KRB5KRB_AP_ERR_MODIFIED;
        numresult = KRB5_KPASSWD_MALFORMED;
        strlcpy(strresult, "Request length was inconsistent",
                sizeof(strresult));
        goto chpwfail;
    }

    /* verify version number */

    vno = (*ptr++ & 0xff) ;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,7 +52,7 @@
         ret = KRB5KRB_AP_ERR_MODIFIED;
         numresult = KRB5_KPASSWD_MALFORMED;
         strlcpy(strresult, "Request was truncated", sizeof(strresult));
-        goto chpwfail;
+        goto bailout;
     }
 
     ptr = req->data;
@@ -67,7 +67,7 @@
         numresult = KRB5_KPASSWD_MALFORMED;
         strlcpy(strresult, "Request length was inconsistent",
                 sizeof(strresult));
-        goto chpwfail;
+        goto bailout;
     }
 
     /* verify version number */
@@ -80,7 +80,7 @@
         numresult = KRB5_KPASSWD_BAD_VERSION;
         snprintf(strresult, sizeof(strresult),
                  "Request contained unknown protocol version number %d", vno);
-        goto chpwfail;
+        goto bailout;
     }
 
     /* read, check ap-req length */
@@ -93,7 +93,7 @@
         numresult = KRB5_KPASSWD_MALFORMED;
         strlcpy(strresult, "Request was truncated in AP-REQ",
                 sizeof(strresult));
-        goto chpwfail;
+        goto bailout;
     }
 
     /* verify ap_req */
```
