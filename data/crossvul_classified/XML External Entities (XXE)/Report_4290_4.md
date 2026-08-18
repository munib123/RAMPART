# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4290_4
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4290_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 8-48 of the vulnerable file.

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

package net.sf.mpxj.conceptdraw;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.UnmarshallerHandler;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLFilter;
import org.xml.sax.XMLReader;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,6 @@
 
 import java.io.IOException;
 import java.io.InputStream;
-import java.io.InputStreamReader;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.Comparator;
@@ -36,16 +35,9 @@
 
 import javax.xml.bind.JAXBContext;
 import javax.xml.bind.JAXBException;
-import javax.xml.bind.Unmarshaller;
-import javax.xml.bind.UnmarshallerHandler;
 import javax.xml.parsers.ParserConfigurationException;
-import javax.xml.parsers.SAXParser;
-import javax.xml.parsers.SAXParserFactory;
-
-import org.xml.sax.InputSource;
+
 import org.xml.sax.SAXException;
-import org.xml.sax.XMLFilter;
-import org.xml.sax.XMLReader;
 
 import net.sf.mpxj.DateRange;
 import net.sf.mpxj.Duration;
@@ -65,6 +57,7 @@
 import net.sf.mpxj.Task;
 import net.sf.mpxj.TimeUnit;
 import net.sf.mpxj.common.AlphanumComparator;
+import net.sf.mpxj.common.UnmarshalHelper;
 import net.sf.mpxj.conceptdraw.schema.Document;
 import net.sf.mpxj.conceptdraw.schema.Document.Calendars.Calendar;
 import net.sf.mpxj.conceptdraw.schema.Document.Calendars.Calendar.ExceptedDays.ExceptedDay;
@@ -99,6 +92,11 @@
    {
       try
       {
+         if (CONTEXT == null)
+         {
+            throw CONTEXT_EXCEPTION;
+         }
+
          m_projectFile = new ProjectFile();
          m_eventManager = m_projectFile.getEventManager();
          m_calendarMap = new HashMap<>();
@@ -113,23 +111,7 @@
 
          m_eventManager.addProjectListeners(m_projectListeners);
 
-         SAXParserFactory factory = SAXParserFactory.newInstance();
-         SAXParser saxParser = factory.newSAXParser();
-         XMLReader xmlReader = saxParser.getXMLReader();
-
-         if (CONTEXT == null)
-         {
-            throw CONTEXT_EXCEPTION;
-         }
-
-         Unmarshaller unmarshaller = CONTEXT.createUnmarshaller();
-
-         XMLFilter filter = new NamespaceFilter();
-         filter.setParent(xmlReader);
-         UnmarshallerHandler unmarshallerHandler = unmarshaller.getUnmarshallerHandler();
-         filter.setContentHandler(unmarshallerHandler);
-         filter.parse(new InputSource(new InputStreamReader(stream)));
-         Document cdp = (Document) unmarshallerHandler.getResult();
+         Document cdp = (Document) UnmarshalHelper.unmarshal(CONTEXT, stream, new NamespaceFilter());
 
          readProjectProperties(cdp);
          readCalendars(cdp);
```
