# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 44_2
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `44_2`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 135-175 of the vulnerable file.

        if (localName != null) {
            answer = cache.get(localName);
        } else {
            localName = "";
        }

        if (answer == null) {
            answer = createQName(localName, namespace, qName);
            answer.setDocumentFactory(documentFactory);
            cache.put(localName, answer);
        }

        return answer;
    }

    public QName get(String qualifiedName, String uri) {
        int index = qualifiedName.indexOf(':');

        if (index < 0) {
            return get(qualifiedName, Namespace.get(uri));
        } else {
            String name = qualifiedName.substring(index + 1);
            String prefix = qualifiedName.substring(0, index);

            return get(name, Namespace.get(prefix, uri));
        }
    }

    /**
     * DOCUMENT ME!
     * 
     * @param qname
     *            DOCUMENT ME!
     * 
     * @return the cached QName instance if there is one or adds the given qname
     *         to the cache if not
     */
    public QName intern(QName qname) {
        return get(qname.getName(), qname.getNamespace(), qname
                .getQualifiedName());
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,6 +152,8 @@
 
         if (index < 0) {
             return get(qualifiedName, Namespace.get(uri));
+        } else if (index == 0){
+            throw new IllegalArgumentException("Qualified name cannot start with ':'.");
         } else {
             String name = qualifiedName.substring(index + 1);
             String prefix = qualifiedName.substring(0, index);
```
