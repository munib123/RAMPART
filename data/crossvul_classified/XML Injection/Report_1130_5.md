# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 1130_5
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1130_5`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 1-39 of the vulnerable file.

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

import java.awt.Component;
import java.beans.XMLDecoder;
import java.io.*;
import java.util.*;

import org.apache.commons.io.FileUtils;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.*;

/**
 * An object of this class stores information about function starts (and returns) to analyze.
 * 
 * <p> There are two possible sources for this information.  The first is a directory containing 
 * XML files produced by JAXB from FunctionBitPatternInfo objects.  The second is a single program.
 */

public class FileBitPatternInfoReader {

	private List<FunctionBitPatternInfo> fInfoList; //list of all function starts and returns to analyze
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,7 +16,6 @@
 package ghidra.bitpatterns.info;
 
 import java.awt.Component;
-import java.beans.XMLDecoder;
 import java.io.*;
 import java.util.*;
 
@@ -184,23 +183,19 @@
 		numFiles++;
 
 		FileBitPatternInfo fileInfo = null;
-		try (XMLDecoder xmlDecoder = new XMLDecoder(new FileInputStream(dataFile))) {
-			fileInfo = (FileBitPatternInfo) xmlDecoder.readObject();
-		}
-		catch (ArrayIndexOutOfBoundsException e) {
-			// Probably wrong type of XML file...skip
+		try {
+			fileInfo = FileBitPatternInfo.fromXmlFile(dataFile);
 		}
 		catch (IOException e) {
-			Msg.error(this, "IOException", e);
-		}
-		if (fileInfo == null) {
-			Msg.info(this, "null FileBitPatternInfo for " + dataFile);
+			Msg.error(this, "Error reading FileBitPatternInfo file " + dataFile, e);
 			return;
 		}
+
 		if (fileInfo.getFuncBitPatternInfo() == null) {
 			Msg.info(this, "fList.getFuncBitPatternInfoList null for " + dataFile);
 			return;
 		}
+
 		if (params == null) {
 			//TODO: this will set the params to the params of the first valid file
 			//these should agree with the parameters for all of the files
```
