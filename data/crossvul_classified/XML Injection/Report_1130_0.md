# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 1130_0
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1130_0`)

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
//This script dumps information about byte and instructions in neighborhoods around function starts
//and returns to an XML file
//@category FunctionStartPatterns
import java.beans.XMLEncoder;
import java.io.*;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.bitpatterns.info.*;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.Msg;

/**
 * Example of command to run this script headlessly:
 * ./analyzeHeadless /local/ghidraProjects/nonShared/ arm -recursive -process -noanalysis -postScript DumpFunctionPatternInfo.java
 */
public class DumpFunctionPatternInfoScript extends GhidraScript {
	private static int totalFuncs = 0;
	private static int programsAnalyzed = 0;

	@Override
	protected void run() throws Exception {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,7 +16,6 @@
 //This script dumps information about byte and instructions in neighborhoods around function starts
 //and returns to an XML file
 //@category FunctionStartPatterns
-import java.beans.XMLEncoder;
 import java.io.*;
 import java.util.List;
 
@@ -118,10 +117,7 @@
 		File savedFile = new File(saveDir.getAbsolutePath() + File.separator +
 			currentProgram.getDomainFile().getPathname().replaceAll("/", "_") + "_" +
 			currentProgram.getExecutableMD5() + "_funcInfo.xml");
-		try (XMLEncoder xmlEncoder =
-			new XMLEncoder(new BufferedOutputStream(new FileOutputStream(savedFile)))) {
-			xmlEncoder.writeObject(funcPatternList);
-		}
+		funcPatternList.toXmlFile(savedFile);
 		Msg.info(this,
 			"Programs analyzed: " + programsAnalyzed + "; total functions: " + totalFuncs);
 	}
```
