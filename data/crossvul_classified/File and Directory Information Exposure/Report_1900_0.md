# CrossVul Fix Pair: Insertion of Sensitive Information into Externally-Accessible File or Directory in java
**Pair ID:** 1900_0
**Vulnerability Class:** File and Directory Information Exposure
**CWE:** CWE-538
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1900_0`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Externally-Accessible File or Directory - The product places sensitive information into files or directories that are accessible to actors who are allowed to have access to the files, but not to the sensitive information.

## Vulnerable Code
```java
Lines 1-33 of the vulnerable file.

package io.onedev.server.migration;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.DumperOptions.FlowStyle;
import org.yaml.snakeyaml.emitter.Emitter;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.SequenceNode;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.resolver.Resolver;
import org.yaml.snakeyaml.serializer.Serializer;

import com.google.common.collect.Lists;

import io.onedev.commons.utils.StringUtils;

public class XmlBuildSpecMigrator {

	private static Node migrateParamSpec(Element paramSpecElement) {
		String classTag = getClassTag(paramSpecElement.getName());
		List<NodeTuple> tuples = new ArrayList<>();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
 import org.dom4j.DocumentException;
 import org.dom4j.Element;
 import org.dom4j.io.SAXReader;
+import org.xml.sax.SAXException;
 import org.yaml.snakeyaml.DumperOptions;
 import org.yaml.snakeyaml.DumperOptions.FlowStyle;
 import org.yaml.snakeyaml.emitter.Emitter;
@@ -662,8 +663,11 @@
 	public static String migrate(String xml) {
 		Document xmlDoc;
 		try {
-			xmlDoc = new SAXReader().read(new StringReader(xml));
-		} catch (DocumentException e) {
+			SAXReader reader = new SAXReader();
+			// Prevent XXE attack as the xml might be provided by malicious users
+			reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+			xmlDoc = reader.read(new StringReader(xml));
+		} catch (DocumentException | SAXException e) {
 			throw new RuntimeException(e);
 		}
 		
```
