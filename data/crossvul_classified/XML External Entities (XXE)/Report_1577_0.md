# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1577_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1577_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-41 of the vulnerable file.

/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq.artemis.selector.filter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

import org.apache.xpath.CachedXPathAPI;
import org.apache.xpath.objects.XObject;
import org.w3c.dom.Document;
import org.w3c.dom.traversal.NodeIterator;
import org.xml.sax.InputSource;


public class XalanXPathEvaluator implements XPathExpression.XPathEvaluator
{

   private final String xpath;

   public XalanXPathEvaluator(String xpath)
   {
      this.xpath = xpath;
   }

   public boolean evaluate(Filterable m) throws FilterException
   {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,7 @@
 
 import javax.xml.parsers.DocumentBuilder;
 import javax.xml.parsers.DocumentBuilderFactory;
+import javax.xml.parsers.ParserConfigurationException;
 import java.io.StringReader;
 
 import org.apache.xpath.CachedXPathAPI;
@@ -56,9 +57,7 @@
    {
       try
       {
-         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
-         factory.setNamespaceAware(true);
-         DocumentBuilder dbuilder = factory.newDocumentBuilder();
+         DocumentBuilder dbuilder = createDocumentBuilder();
          Document doc = dbuilder.parse(inputSource);
 
          //An XPath expression could return a true or false value instead of a node.
@@ -75,11 +74,22 @@
             NodeIterator iterator = cachedXPathAPI.selectNodeIterator(doc, xpath);
             return (iterator.nextNode() != null);
          }
-
       }
       catch (Throwable e)
       {
          return false;
       }
    }
+
+   private DocumentBuilder createDocumentBuilder() throws ParserConfigurationException
+   {
+      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+      factory.setNamespaceAware(true);
+
+      factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+
+      return factory.newDocumentBuilder();
+   }
 }
```
