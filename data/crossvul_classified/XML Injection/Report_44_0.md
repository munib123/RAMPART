# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 44_0
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `44_0`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 32-72 of the vulnerable file.

    /** The prefix mapped to this namespace */
    private String prefix;

    /** The URI for this namespace */
    private String uri;

    /** A cached version of the hashcode for efficiency */
    private int hashCode;

    /**
     * DOCUMENT ME!
     * 
     * @param prefix
     *            is the prefix for this namespace
     * @param uri
     *            is the URI for this namespace
     */
    public Namespace(String prefix, String uri) {
        this.prefix = (prefix != null) ? prefix : "";
        this.uri = (uri != null) ? uri : "";
    }

    /**
     * A helper method to return the Namespace instance for the given prefix and
     * URI
     * 
     * @param prefix
     *            DOCUMENT ME!
     * @param uri
     *            DOCUMENT ME!
     * 
     * @return an interned Namespace object
     */
    public static Namespace get(String prefix, String uri) {
        return CACHE.get(prefix, uri);
    }

    /**
     * A helper method to return the Namespace instance for no prefix and the
     * URI
     * 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,6 +49,10 @@
     public Namespace(String prefix, String uri) {
         this.prefix = (prefix != null) ? prefix : "";
         this.uri = (uri != null) ? uri : "";
+
+        if (!this.prefix.isEmpty()) {
+            QName.validateNCName(this.prefix);
+        }
     }
 
     /**
```
