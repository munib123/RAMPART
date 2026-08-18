# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1397_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1397_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-22 of the vulnerable file.

/*
 * Copyright 2017 - 2018 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.protocol;

import com.fasterxml.jackson.databind.util.ByteBufferBackedInputStream;
import io.netty.channel.Channel;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.traccar.BaseHttpProtocolDecoder;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * Copyright 2017 - 2018 Anton Tananaev (anton@traccar.org)
+ * Copyright 2017 - 2019 Anton Tananaev (anton@traccar.org)
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -49,7 +49,14 @@
     public SpotProtocolDecoder(Protocol protocol) {
         super(protocol);
         try {
-            documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
+            DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
+            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+            builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+            builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+            builderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+            builderFactory.setXIncludeAware(false);
+            builderFactory.setExpandEntityReferences(false);
+            documentBuilder = builderFactory.newDocumentBuilder();
             xPath = XPathFactory.newInstance().newXPath();
             messageExpression = xPath.compile("//messageList/message");
         } catch (ParserConfigurationException | XPathExpressionException e) {
```
