# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 3875_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3875_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 1-36 of the vulnerable file.

/*
 * Copyright 2001-2005 (C) MetaStuff, Ltd. All Rights Reserved.
 *
 * This software is open source.
 * See the bottom of this file for the licence.
 */

package org.dom4j.io;

import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

/**
 * <p>
 * <code>SAXHelper</code> contains some helper methods for working with SAX
 * and XMLReader objects.
 * </p>
 * 
 * @author <a href="mailto:james.strachan@metastuff.com">James Strachan </a>
 * @version $Revision: 1.18 $
 */
class SAXHelper {
    private static boolean loggedWarning = true;

    protected SAXHelper() {
    }

    public static boolean setParserProperty(XMLReader reader,
            String propertyName, Object value) {
        try {
            reader.setProperty(propertyName, value);

            return true;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,12 +13,14 @@
 import org.xml.sax.XMLReader;
 import org.xml.sax.helpers.XMLReaderFactory;
 
+import javax.xml.parsers.SAXParserFactory;
+
 /**
  * <p>
  * <code>SAXHelper</code> contains some helper methods for working with SAX
  * and XMLReader objects.
  * </p>
- * 
+ *
  * @author <a href="mailto:james.strachan@metastuff.com">James Strachan </a>
  * @version $Revision: 1.18 $
  */
@@ -61,12 +63,21 @@
     /**
      * Creats a default XMLReader via the org.xml.sax.driver system property or
      * JAXP if the system property is not set.
-     * 
+     *
+     * This method internally calls {@link SAXParserFactory}{@code .newInstance().newSAXParser().getXMLReader()} or {@link XMLReaderFactory#createXMLReader()}.
+     * Be sure to configure returned reader if the default configuration does not suit you. Consider setting the following properties:
+     *
+     * <pre>
+     * reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+     * reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
+     * reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+     * </pre>
+     *
      * @param validating
      *            DOCUMENT ME!
-     * 
+     *
      * @return DOCUMENT ME!
-     * 
+     *
      * @throws SAXException
      *             DOCUMENT ME!
      */
@@ -125,12 +136,12 @@
      * This method attempts to use JAXP to locate the SAX2 XMLReader
      * implementation. This method uses reflection to avoid being dependent
      * directly on the JAXP classes.
-     * 
+     *
      * @param validating
      *            DOCUMENT ME!
      * @param namespaceAware
      *            DOCUMENT ME!
-     * 
+     *
      * @return DOCUMENT ME!
      */
     protected static XMLReader createXMLReaderViaJAXP(boolean validating,
@@ -176,24 +187,24 @@
  * Redistribution and use of this software and associated documentation
  * ("Software"), with or without modification, are permitted provided that the
  * following conditions are met:
- * 
+ *
  * 1. Redistributions of source code must retain copyright statements and
  * notices. Redistributions must also contain a copy of this document.
- * 
+ *
  * 2. Redistributions in binary form must reproduce the above copyright notice,
  * this list of conditions and the following disclaimer in the documentation
  * and/or other materials provided with the distribution.
- * 
+ *
  * 3. The name "DOM4J" must not be used to endorse or promote products derived
  * from this Software without prior written permission of MetaStuff, Ltd. For
  * written permission, please contact dom4j-info@metastuff.com.
- * 
+ *
  * 4. Products derived from this Software may not be called "DOM4J" nor may
  * "DOM4J" appear in their names without prior written permission of MetaStuff,
  * Ltd. DOM4J is a registered trademark of MetaStuff, Ltd.
- * 
+ *
  * 5. Due credit should be given to the DOM4J Project - http://www.dom4j.org
- * 
+ *
  * THIS SOFTWARE IS PROVIDED BY METASTUFF, LTD. AND CONTRIBUTORS ``AS IS'' AND
  * ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
@@ -205,6 +216,6 @@
  * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  * POSSIBILITY OF SUCH DAMAGE.
- * 
+ *
  * Copyright 2001-2005 (C) MetaStuff, Ltd. All Rights Reserved.
  */
```
