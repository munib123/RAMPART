# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_2
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-37 of the vulnerable file.

/**
 * Copyright (c) 2010-2020 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.avmfritz.internal.util;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.avmfritz.internal.dto.DeviceListModel;
import org.openhab.binding.avmfritz.internal.dto.templates.TemplateListModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation for a static use of JAXBContext as singleton instance.
 *
 * @author Christoph Weitkamp - Initial contribution
 */
@NonNullByDefault
public class JAXBUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JAXBUtils.class);

    public static final @Nullable JAXBContext JAXBCONTEXT_DEVICES = initJAXBContextDevices();
    public static final @Nullable JAXBContext JAXBCONTEXT_TEMPLATES = initJAXBContextTemplates();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,6 +14,7 @@
 
 import javax.xml.bind.JAXBContext;
 import javax.xml.bind.JAXBException;
+import javax.xml.stream.XMLInputFactory;
 
 import org.eclipse.jdt.annotation.NonNullByDefault;
 import org.eclipse.jdt.annotation.Nullable;
@@ -34,6 +35,7 @@
 
     public static final @Nullable JAXBContext JAXBCONTEXT_DEVICES = initJAXBContextDevices();
     public static final @Nullable JAXBContext JAXBCONTEXT_TEMPLATES = initJAXBContextTemplates();
+    public static final XMLInputFactory XMLINPUTFACTORY = initXMLInputFactory();
 
     private static @Nullable JAXBContext initJAXBContextDevices() {
         try {
@@ -52,4 +54,11 @@
             return null;
         }
     }
+
+    private static XMLInputFactory initXMLInputFactory() {
+        XMLInputFactory xif = XMLInputFactory.newInstance();
+        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
+        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
+        return xif;
+    }
 }
```
