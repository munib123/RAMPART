# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in java
**Pair ID:** 4708_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4708_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```java
Lines 1-27 of the vulnerable file.

package org.orbeon.oxf.xml.xerces;

import org.orbeon.oxf.common.OXFException;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;

/**
 * Boasts a couple of improvements over the 'stock' xerces parser factory.
 *
 * o Doesn't create a new parser every time one calls setFeature or getFeature.  Stock one
 *   has to do this because valid feature set is encapsulated in the parser code.
 *
 * o Creates a XercesJAXPSAXParser instead of SaxParserImpl. See XercesJAXPSAXParser for
 *   why this is an improvement.
 *
 * o The improvements cut the time it takes to a SAX parser via JAXP in
 *   half and reduce the amount of garbage created when accessing '/' in
 *   the examples app from 9019216 bytes to 8402880 bytes.
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,13 +4,9 @@
 import org.xml.sax.SAXException;
 import org.xml.sax.SAXNotRecognizedException;
 
-import javax.xml.parsers.ParserConfigurationException;
 import javax.xml.parsers.SAXParser;
 import javax.xml.parsers.SAXParserFactory;
-import java.util.Collection;
-import java.util.Collections;
-import java.util.Hashtable;
-import java.util.Map;
+import java.util.*;
 
 /**
  * Boasts a couple of improvements over the 'stock' xerces parser factory.
@@ -42,23 +38,17 @@
     static {
         {
             final OrbeonParserConfiguration configuration = XercesSAXParser.makeConfig(false, true);
-            final Collection features = configuration.getRecognizedFeatures();
-            recognizedFeaturesNonValidatingXInclude = Collections.unmodifiableCollection(features);
+            final Collection recognizedFeatures = configuration.getRecognizedFeatures();
+            recognizedFeaturesNonValidatingXInclude = Collections.unmodifiableCollection(recognizedFeatures);
             defaultFeaturesNonValidatingXInclude = configuration.getFeatures();
-            // This was being done in XMLUtils.createSaxParserFactory before.  Maybe want to
-            // move it back if we decide to make this class more general purpose.
-            defaultFeaturesNonValidatingXInclude.put("http://xml.org/sax/features/namespaces", Boolean.TRUE);
-            defaultFeaturesNonValidatingXInclude.put("http://xml.org/sax/features/namespace-prefixes", Boolean.FALSE);
+            addDefaultFeatures(defaultFeaturesNonValidatingXInclude);
         }
         {
             final OrbeonParserConfiguration configuration = XercesSAXParser.makeConfig(false, false);
             final Collection features = configuration.getRecognizedFeatures();
             recognizedFeaturesNonValidatingNoXInclude = Collections.unmodifiableCollection(features);
             defaultFeaturesNonValidatingNoXInclude = configuration.getFeatures();
-            // This was being done in XMLUtils.createSaxParserFactory before.  Maybe want to
-            // move it back if we decide to make this class more general purpose.
-            defaultFeaturesNonValidatingNoXInclude.put("http://xml.org/sax/features/namespaces", Boolean.TRUE);
-            defaultFeaturesNonValidatingNoXInclude.put("http://xml.org/sax/features/namespace-prefixes", Boolean.FALSE);
+            addDefaultFeatures(defaultFeaturesNonValidatingNoXInclude);
         }
 
         {
@@ -66,21 +56,23 @@
             final Collection features = configuration.getRecognizedFeatures();
             recognizedFeaturesValidatingXInclude = Collections.unmodifiableCollection(features);
             defaultFeaturesValidatingXInclude = configuration.getFeatures();
-            // This was being done in XMLUtils.createSaxParserFactory before.  Maybe want to
-            // move it back if we decide to make this class more general purpose.
-            defaultFeaturesValidatingXInclude.put("http://xml.org/sax/features/namespaces", Boolean.TRUE);
-            defaultFeaturesValidatingXInclude.put("http://xml.org/sax/features/namespace-prefixes", Boolean.FALSE);
+            addDefaultFeatures(defaultFeaturesValidatingXInclude);
         }
         {
             final OrbeonParserConfiguration configuration = XercesSAXParser.makeConfig(true, false);
             final Collection features = configuration.getRecognizedFeatures();
             recognizedFeaturesValidatingNoXInclude = Collections.unmodifiableCollection(features);
             defaultFeaturesValidatingNoXInclude = configuration.getFeatures();
-            // This was being done in XMLUtils.createSaxParserFactory before.  Maybe want to
-            // move it back if we decide to make this class more general purpose.
-            defaultFeaturesValidatingNoXInclude.put("http://xml.org/sax/features/namespaces", Boolean.TRUE);
-            defaultFeaturesValidatingNoXInclude.put("http://xml.org/sax/features/namespace-prefixes", Boolean.FALSE);
+            addDefaultFeatures(defaultFeaturesValidatingNoXInclude);
         }
+    }
+
+    private static void addDefaultFeatures(Map features) {
+        features.put("http://xml.org/sax/features/namespaces", Boolean.TRUE);
+        features.put("http://xml.org/sax/features/namespace-prefixes", Boolean.FALSE);
+        // For security purposes, disable external entities
+        features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
+        features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
     }
 
     private final Hashtable features;
@@ -112,14 +104,13 @@
         features.put(key, val ? Boolean.TRUE : Boolean.FALSE);
     }
 
-    public SAXParser newSAXParser() throws ParserConfigurationException {
+    public SAXParser newSAXParser() {
         final SAXParser ret;
         try {
             ret = new XercesJAXPSAXParser(this, features, validating, handleXInclude);
         } catch (final SAXException se) {
             // Translate to ParserConfigurationException
             throw new OXFException(se); // so we see a decent stack trace!
-//            throw new ParserConfigurationException(se.getMessage());
         }
         return ret;
     }
```
