# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 657_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `657_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 45-85 of the vulnerable file.

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Few simple utils to read DOM. This is originally from the Jakarta Commons Modeler.
 *
 * @author Costin Manolache
 */
public final class DOMUtils {
    private static final Logger LOG = LoggerFactory.getLogger(DOMUtils.class);
    
    private static final String XMLNAMESPACE = "xmlns";

    private static final DocumentBuilderFactory DBF = DocumentBuilderFactory.newInstance();
    
    static {
        try {
            DBF.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            DBF.setValidating(false);
            DBF.setIgnoringComments(false);
            DBF.setIgnoringElementContentWhitespace(true);
            DBF.setNamespaceAware(true);
            // DBF.setCoalescing(true);
            // DBF.setExpandEntityReferences(true);
        } catch (ParserConfigurationException ex) {
            LOG.error("Error configuring DocumentBuilderFactory", ex);
        }
    }

    private DOMUtils() {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,14 +62,15 @@
  */
 public final class DOMUtils {
     private static final Logger LOG = LoggerFactory.getLogger(DOMUtils.class);
-    
+
     private static final String XMLNAMESPACE = "xmlns";
 
     private static final DocumentBuilderFactory DBF = DocumentBuilderFactory.newInstance();
-    
+
     static {
         try {
             DBF.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+            DBF.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
 
             DBF.setValidating(false);
             DBF.setIgnoringComments(false);
```
