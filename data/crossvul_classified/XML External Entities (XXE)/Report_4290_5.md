# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4290_5
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4290_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 14-54 of the vulnerable file.

 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

package net.sf.mpxj.ganttdesigner;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
import net.sf.mpxj.Day;
import net.sf.mpxj.EventManager;
import net.sf.mpxj.MPXJException;
import net.sf.mpxj.ProjectCalendar;
import net.sf.mpxj.ProjectCalendarException;
import net.sf.mpxj.ProjectCalendarHours;
import net.sf.mpxj.ProjectCalendarWeek;
import net.sf.mpxj.ProjectConfig;
import net.sf.mpxj.ProjectFile;
import net.sf.mpxj.ProjectProperties;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,15 +31,9 @@
 
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
 import net.sf.mpxj.Day;
@@ -54,6 +48,7 @@
 import net.sf.mpxj.ProjectProperties;
 import net.sf.mpxj.RelationType;
 import net.sf.mpxj.Task;
+import net.sf.mpxj.common.UnmarshalHelper;
 import net.sf.mpxj.ganttdesigner.schema.Gantt;
 import net.sf.mpxj.ganttdesigner.schema.GanttDesignerRemark;
 import net.sf.mpxj.listener.ProjectListener;
@@ -83,6 +78,11 @@
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
          m_taskMap = new HashMap<>();
@@ -95,19 +95,7 @@
 
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
-         Gantt gantt = (Gantt) unmarshaller.unmarshal(doc);
+         Gantt gantt = (Gantt) UnmarshalHelper.unmarshal(CONTEXT, stream);
 
          readProjectProperties(gantt);
          readCalendar(gantt);
```
