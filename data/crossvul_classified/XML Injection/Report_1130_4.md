# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 1130_4
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1130_4`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 1-38 of the vulnerable file.

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.bitpatterns.info;

import java.util.ArrayList;
import java.util.List;

/**
 * An object of this class stores all the function bit pattern information for an executable.
 * It records the number of bytes and instructions for each category (first, pre, and return), as
 * well as the language ID and ghidraURL of the executable.  Using JAXB, objects of this class converted
 * to/from XML files for analysis and storage.
 */

public class FileBitPatternInfo {

	private int numFirstBytes = 0;
	private int numFirstInstructions = 0;
	private int numPreBytes = 0;
	private int numPreInstructions = 0;
	private int numReturnBytes = 0;
	private int numReturnInstructions = 0;
	private String languageID = null;
	private String ghidraURL = null;
	private List<FunctionBitPatternInfo> funcBitPatternInfo;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,8 +15,15 @@
  */
 package ghidra.bitpatterns.info;
 
+import java.io.*;
 import java.util.ArrayList;
 import java.util.List;
+
+import org.jdom.*;
+import org.jdom.input.SAXBuilder;
+
+import ghidra.util.Msg;
+import ghidra.util.xml.XmlUtilities;
 
 /**
  * An object of this class stores all the function bit pattern information for an executable.
@@ -26,6 +33,8 @@
  */
 
 public class FileBitPatternInfo {
+
+	static final String XML_ELEMENT_NAME = "FileBitPatternInfo";
 
 	private int numFirstBytes = 0;
 	private int numFirstInstructions = 0;
@@ -195,4 +204,110 @@
 	public void setNumReturnInstructions(int numReturnInstructions) {
 		this.numReturnInstructions = numReturnInstructions;
 	}
+
+	/**
+	 * Converts this object into XML
+	 * 
+	 * @return new jdom {@link Element}
+	 */
+	public Element toXml() {
+		Element result = new Element(XML_ELEMENT_NAME);
+		XmlUtilities.setStringAttr(result, "ghidraURL", ghidraURL);
+		XmlUtilities.setStringAttr(result, "languageID", languageID);
+		XmlUtilities.setIntAttr(result, "numFirstBytes", numFirstBytes);
+		XmlUtilities.setIntAttr(result, "numFirstInstructions", numFirstInstructions);
+		XmlUtilities.setIntAttr(result, "numPreBytes", numPreBytes);
+		XmlUtilities.setIntAttr(result, "numPreInstructions", numPreInstructions);
+		XmlUtilities.setIntAttr(result, "numReturnBytes", numReturnBytes);
+		XmlUtilities.setIntAttr(result, "numReturnInstructions", numReturnInstructions);
+
+		Element funcBitPatternInfoListEle = new Element("funcBitPatternInfoList");
+		for (FunctionBitPatternInfo fbpi : funcBitPatternInfo) {
+			funcBitPatternInfoListEle.addContent(fbpi.toXml());
+		}
+
+		result.addContent(funcBitPatternInfoListEle);
+
+		return result;
+	}
+
+	/**
+	 * Creates a {@link FileBitPatternInfo} instance from XML.
+	 * 
+	 * @param e XML element to convert
+	 * @return new {@link FileBitPatternInfo}, never null
+	 * @throws IOException if file IO error or xml data problem
+	 */
+	public static FileBitPatternInfo fromXml(Element e) throws IOException {
+
+		String ghidraURL = e.getAttributeValue("ghidraURL");
+		String languageID = e.getAttributeValue("languageID");
+		int numFirstBytes =
+			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numFirstBytes"));
+		int numFirstInstructions =
+			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numFirstInstructions"));
+		int numPreBytes = XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numPreBytes"));
+		int numPreInstructions =
+			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numPreInstructions"));
+		int numReturnBytes =
+			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numReturnBytes"));
+		int numReturnInstructions =
+			XmlUtilities.parseInt(XmlUtilities.requireStringAttr(e, "numReturnInstructions"));
+
+		List<FunctionBitPatternInfo> funcBitPatternInfoList = new ArrayList<>();
+		Element funcBitPatternInfoListEle = e.getChild("funcBitPatternInfoList");
+		if (funcBitPatternInfoListEle != null) {
+			for (Element childElement : XmlUtilities.getChildren(funcBitPatternInfoListEle,
+				FunctionBitPatternInfo.XML_ELEMENT_NAME)) {
+				funcBitPatternInfoList.add(FunctionBitPatternInfo.fromXml(childElement));
+			}
+		}
+
+		FileBitPatternInfo result = new FileBitPatternInfo();
+		result.setFuncBitPatternInfo(funcBitPatternInfoList);
+		result.setGhidraURL(ghidraURL);
+		result.setLanguageID(languageID);
+		result.setNumFirstBytes(numFirstBytes);
+		result.setNumFirstInstructions(numFirstInstructions);
+		result.setNumPreBytes(numPreBytes);
+		result.setNumPreInstructions(numPreInstructions);
+		result.setNumReturnBytes(numReturnBytes);
+		result.setNumReturnInstructions(numReturnInstructions);
+
+		return result;
+	}
+
+	/**
+	 * Converts this object to XML and writes it to the specified file.
+	 * 
+	 * @param destFile name of xml file to create
+	 * @throws IOException if file io error
+	 */
+	public void toXmlFile(File destFile) throws IOException {
+		Element rootEle = toXml();
+		Document doc = new Document(rootEle);
+
+		XmlUtilities.writePrettyDocToFile(doc, destFile);
+	}
+
+	/**
+	 * Creates a {@link FileBitPatternInfo} instance from a XML file.
+	 * 
+	 * @param inputFile name of xml file to read
+	 * @return new {@link FileBitPatternInfo} instance, never null
+	 * @throws IOException if file io error or xml data format problem 
+	 */
+	public static FileBitPatternInfo fromXmlFile(File inputFile) throws IOException {
+		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
+		try (InputStream fis = new FileInputStream(inputFile)) {
+			Document doc = sax.build(fis);
+			Element rootElem = doc.getRootElement();
+			return fromXml(rootElem);
+		}
+		catch (JDOMException | IOException e) {
+			Msg.error(FileBitPatternInfo.class, "Bad file bit pattern file " + inputFile, e);
+			throw new IOException("Failed to read file bit pattern " + inputFile, e);
+		}
+
+	}
 }
```
