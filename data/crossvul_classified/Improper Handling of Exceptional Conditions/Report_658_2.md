# CrossVul Fix Pair: Improper Handling of Exceptional Conditions in java
**Pair ID:** 658_2
**Vulnerability Class:** Improper Handling of Exceptional Conditions
**CWE:** CWE-755
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `658_2`)

## Vulnerability Information & PoC

## Description
Improper Handling of Exceptional Conditions - The product does not handle or incorrectly handles an exceptional condition.

## Vulnerable Code
```java
Lines 110-150 of the vulnerable file.

            switch (hostFormat) {
            case IPv4:
                matchIPAddress(host, subjectAlts);
                break;
            case IPv6:
                matchIPv6Address(host, subjectAlts);
                break;
            default:
                matchDNSName(host, subjectAlts, this.publicSuffixMatcher);
            }
        } else {
            // CN matching has been deprecated by rfc2818 and can be used
            // as fallback only when no subjectAlts are available
            final X500Principal subjectPrincipal = cert.getSubjectX500Principal();
            final String cn = extractCN(subjectPrincipal.getName(X500Principal.RFC2253));
            if (cn == null) {
                throw new SSLException("Certificate subject for <" + host + "> doesn't contain "
                    + "a common name and does not have alternative names");
            }
            matchCN(host, cn, this.publicSuffixMatcher);
        }
    }

    static void matchIPAddress(final String host, final List<String> subjectAlts) throws SSLException {
        for (int i = 0; i < subjectAlts.size(); i++) {
            final String subjectAlt = subjectAlts.get(i);
            if (host.equals(subjectAlt)) {
                return;
            }
        }
        throw new SSLException("Certificate for <" + host + "> doesn't match any "
            + "of the subject alternative names: " + subjectAlts);
    }

    static void matchIPv6Address(final String host, final List<String> subjectAlts) throws SSLException {
        final String normalisedHost = normaliseAddress(host);
        for (int i = 0; i < subjectAlts.size(); i++) {
            final String subjectAlt = subjectAlts.get(i);
            final String normalizedSubjectAlt = normaliseAddress(subjectAlt);
            if (normalisedHost.equals(normalizedSubjectAlt)) {
                return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -130,6 +130,18 @@
         }
     }
 
+    public boolean verify(final String host, final String certHostname) {
+        try {
+            matchCN(host, certHostname, this.publicSuffixMatcher);
+            return true;
+        } catch (SSLException ex) {
+            if (LOG.isLoggable(Level.FINE)) {
+                LOG.log(Level.FINE, ex.getMessage(), ex);
+            }
+            return false;
+        }
+    }
+
     static void matchIPAddress(final String host, final List<String> subjectAlts) throws SSLException {
         for (int i = 0; i < subjectAlts.size(); i++) {
             final String subjectAlt = subjectAlts.get(i);
```
