# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in java
**Pair ID:** 658_0
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `658_0`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```java
Lines 22-42 of the vulnerable file.

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * Allow all hostnames. This is only suitable for use in testing, and NOT in production!
 */
class AllowAllHostnameVerifier implements javax.net.ssl.HostnameVerifier {

    @Override
    public boolean verify(String host, SSLSession session) {
        try {
            Certificate[] certs = session.getPeerCertificates();
            return certs != null && certs[0] instanceof X509Certificate;
        } catch (SSLException e) {
            return false;
        }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,4 +39,8 @@
             return false;
         }
     }
+
+    public boolean verify(final String host, final String certHostname) {
+        return certHostname != null && !certHostname.isEmpty();
+    }
 }
```
