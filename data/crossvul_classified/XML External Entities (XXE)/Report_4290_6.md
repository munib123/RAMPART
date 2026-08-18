# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4290_6
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4290_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 20-60 of the vulnerable file.

 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

package net.sf.mpxj.ganttproject;

import java.io.InputStream;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import net.sf.mpxj.ChildTaskContainer;
import net.sf.mpxj.ConstraintType;
import net.sf.mpxj.CustomField;
import net.sf.mpxj.Day;
import net.sf.mpxj.Duration;
import net.sf.mpxj.EventManager;
import net.sf.mpxj.FieldType;
import net.sf.mpxj.MPXJException;
import net.sf.mpxj.Priority;
import net.sf.mpxj.ProjectCalendar;
import net.sf.mpxj.ProjectCalendarException;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,15 +37,9 @@
 
 import javax.xml.bind.JAXBContext;
 import javax.xml.bind.JAXBException;
-import javax.xml.bind.Unmarshaller;
 import javax.xml.parsers.ParserConfigurationException;
-import javax.xml.parsers.SAXParser;
-import javax.xml.parsers.SAXParserFactory;
-import javax.xml.transform.sax.SAXSource;
-
-import org.xml.sax.InputSource;
+
 import org.xml.sax.SAXException;
-import org.xml.sax.XMLReader;
 
 import net.sf.mpxj.ChildTaskContainer;
 import net.sf.mpxj.ConstraintType;
@@ -76,6 +70,7 @@
 import net.sf.mpxj.common.Pair;
 import net.sf.mpxj.common.ResourceFieldLists;
 import net.sf.mpxj.common.TaskFieldLists;
+import net.sf.mpxj.common.UnmarshalHelper;
 import net.sf.mpxj.ganttproject.schema.Allocation;
 import net.sf.mpxj.ganttproject.schema.Allocations;
 import net.sf.mpxj.ganttproject.schema.Calendars;
@@ -118,6 +113,11 @@
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
          m_resourcePropertyDefinitions = new HashMap<>();
@@ -137,19 +137,7 @@
 
          m_eventManager.addProjectListeners(m_projectListeners);
 
-         SAXParserFactory factory = SAXParserFactory.newInstance();
-         SAXParser saxParser = factory.newSAXParser();
-         XMLReader xmlReader = saxParser.getXMLReader();
-         SAXSource doc = new SAXSource(xmlReader, new InputSource(stream));
-
-         if (CONTEXT == null)
-         {
-            throw CONTEXT_EXCEPTION;
-         }
-
-         Unmarshaller unmarshaller = CONTEXT.createUnmarshaller();
-
-         Project ganttProject = (Project) unmarshaller.unmarshal(doc);
+         Project ganttProject = (Project) UnmarshalHelper.unmarshal(CONTEXT, stream);
 
          readProjectProperties(ganttProject);
          readCalendars(ganttProject);
```
