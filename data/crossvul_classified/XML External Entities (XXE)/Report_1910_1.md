# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-41 of the vulnerable file.

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
package org.openhab.binding.avmfritz.internal.hardware.callbacks;

import static org.eclipse.jetty.http.HttpMethod.GET;

import java.io.StringReader;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.openhab.binding.avmfritz.internal.dto.templates.TemplateListModel;
import org.openhab.binding.avmfritz.internal.handler.AVMFritzBaseBridgeHandler;
import org.openhab.binding.avmfritz.internal.hardware.FritzAhaWebInterface;
import org.openhab.binding.avmfritz.internal.util.JAXBUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Callback implementation for updating templates from a xml response.
 *
 * @author Christoph Weitkamp - Initial contribution
 */
@NonNullByDefault
public class FritzAhaUpdateTemplatesCallback extends FritzAhaReauthCallback {

    private final Logger logger = LoggerFactory.getLogger(FritzAhaUpdateTemplatesCallback.class);

    private static final String WEBSERVICE_COMMAND = "switchcmd=gettemplatelistinfos";

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,8 @@
 
 import javax.xml.bind.JAXBException;
 import javax.xml.bind.Unmarshaller;
+import javax.xml.stream.XMLStreamException;
+import javax.xml.stream.XMLStreamReader;
 
 import org.eclipse.jdt.annotation.NonNullByDefault;
 import org.openhab.binding.avmfritz.internal.dto.templates.TemplateListModel;
@@ -58,14 +60,15 @@
         logger.trace("Received response '{}'", response);
         if (isValidRequest()) {
             try {
+                XMLStreamReader xsr = JAXBUtils.XMLINPUTFACTORY.createXMLStreamReader(new StringReader(response));
                 Unmarshaller unmarshaller = JAXBUtils.JAXBCONTEXT_TEMPLATES.createUnmarshaller();
-                TemplateListModel model = (TemplateListModel) unmarshaller.unmarshal(new StringReader(response));
+                TemplateListModel model = (TemplateListModel) unmarshaller.unmarshal(xsr);
                 if (model != null) {
                     handler.addTemplateList(model.getTemplates());
                 } else {
                     logger.debug("no template in response");
                 }
-            } catch (JAXBException e) {
+            } catch (JAXBException | XMLStreamException e) {
                 logger.error("Exception creating Unmarshaller: {}", e.getLocalizedMessage(), e);
             }
         } else {
```
