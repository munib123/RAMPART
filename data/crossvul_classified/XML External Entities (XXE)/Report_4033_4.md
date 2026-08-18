# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4033_4
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4033_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-32 of the vulnerable file.

/*
 * Copyright (c) 2004, PostgreSQL Global Development Group
 * See the LICENSE file in the project root for more information.
 */

package org.postgresql.jdbc;

import org.postgresql.core.BaseConnection;
import org.postgresql.util.GT;
import org.postgresql.util.PSQLException;
import org.postgresql.util.PSQLState;

import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.sql.SQLException;
import java.sql.SQLXML;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -9,10 +9,11 @@
 import org.postgresql.util.GT;
 import org.postgresql.util.PSQLException;
 import org.postgresql.util.PSQLState;
-
-import org.xml.sax.ErrorHandler;
+import org.postgresql.xml.DefaultPGXmlFactoryFactory;
+import org.postgresql.xml.PGXmlFactoryFactory;
+
 import org.xml.sax.InputSource;
-import org.xml.sax.SAXParseException;
+import org.xml.sax.XMLReader;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
@@ -27,7 +28,6 @@
 import java.sql.SQLXML;
 
 import javax.xml.parsers.DocumentBuilder;
-import javax.xml.parsers.DocumentBuilderFactory;
 import javax.xml.stream.XMLInputFactory;
 import javax.xml.stream.XMLOutputFactory;
 import javax.xml.stream.XMLStreamException;
@@ -77,6 +77,13 @@
     this.freed = false;
   }
 
+  private PGXmlFactoryFactory getXmlFactoryFactory() throws SQLException {
+    if (conn != null) {
+      return conn.getXmlFactoryFactory();
+    }
+    return DefaultPGXmlFactoryFactory.INSTANCE;
+  }
+
   @Override
   public synchronized void free() {
     freed = true;
@@ -132,18 +139,17 @@
 
     try {
       if (sourceClass == null || DOMSource.class.equals(sourceClass)) {
-        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
-        DocumentBuilder builder = factory.newDocumentBuilder();
-        builder.setErrorHandler(new NonPrintingErrorHandler());
+        DocumentBuilder builder = getXmlFactoryFactory().newDocumentBuilder();
         InputSource input = new InputSource(new StringReader(data));
         return (T) new DOMSource(builder.parse(input));
       } else if (SAXSource.class.equals(sourceClass)) {
+        XMLReader reader = getXmlFactoryFactory().createXMLReader();
         InputSource is = new InputSource(new StringReader(data));
-        return (T) new SAXSource(is);
+        return (T) new SAXSource(reader, is);
       } else if (StreamSource.class.equals(sourceClass)) {
         return (T) new StreamSource(new StringReader(data));
       } else if (StAXSource.class.equals(sourceClass)) {
-        XMLInputFactory xif = XMLInputFactory.newInstance();
+        XMLInputFactory xif = getXmlFactoryFactory().newXMLInputFactory();
         XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(data));
         return (T) new StAXSource(xsr);
       }
@@ -191,8 +197,7 @@
       return (T) domResult;
     } else if (SAXResult.class.equals(resultClass)) {
       try {
-        SAXTransformerFactory transformerFactory =
-            (SAXTransformerFactory) SAXTransformerFactory.newInstance();
+        SAXTransformerFactory transformerFactory = getXmlFactoryFactory().newSAXTransformerFactory();
         TransformerHandler transformerHandler = transformerFactory.newTransformerHandler();
         stringWriter = new StringWriter();
         transformerHandler.setResult(new StreamResult(stringWriter));
@@ -209,7 +214,7 @@
     } else if (StAXResult.class.equals(resultClass)) {
       stringWriter = new StringWriter();
       try {
-        XMLOutputFactory xof = XMLOutputFactory.newInstance();
+        XMLOutputFactory xof = getXmlFactoryFactory().newXMLOutputFactory();
         XMLStreamWriter xsw = xof.createXMLStreamWriter(stringWriter);
         active = true;
         return (T) new StAXResult(xsw);
@@ -272,7 +277,7 @@
       // and use the identify transform to get it into a
       // friendlier result format.
       try {
-        TransformerFactory factory = TransformerFactory.newInstance();
+        TransformerFactory factory = getXmlFactoryFactory().newTransformerFactory();
         Transformer transformer = factory.newTransformer();
         DOMSource domSource = new DOMSource(domResult.getNode());
         StringWriter stringWriter = new StringWriter();
@@ -298,18 +303,4 @@
     }
     initialized = true;
   }
-
-  // Don't clutter System.err with errors the user can't silence.
-  // If something bad really happens an exception will be thrown.
-  static class NonPrintingErrorHandler implements ErrorHandler {
-    public void error(SAXParseException e) {
-    }
-
-    public void fatalError(SAXParseException e) {
-    }
-
-    public void warning(SAXParseException e) {
-    }
-  }
-
 }
```
