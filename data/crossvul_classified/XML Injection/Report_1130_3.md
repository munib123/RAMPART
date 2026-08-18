# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 1130_3
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1130_3`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 1-40 of the vulnerable file.

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

import java.math.BigInteger;

/**
 * class for representing the values a specific context register assumes within a function body. 
 */
public class ContextRegisterInfo {
	String contextRegister;//the context register
	String value;//the value it assumes (needed because a BigInteger will not serialize to xml)
	BigInteger valueAsBigInteger;//the value it assumes

	/**
	 * Default constructor (used by XMLEncoder)
	 */
	public ContextRegisterInfo() {
	}

	/**
	 * Creates a {@link ContextRegisterInfo} object for a specified context register
	 * @param contextRegister
	 */
	public ContextRegisterInfo(String contextRegister) {
		this.contextRegister = contextRegister;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,13 +17,17 @@
 
 import java.math.BigInteger;
 
+import org.jdom.Element;
+
 /**
  * class for representing the values a specific context register assumes within a function body. 
  */
 public class ContextRegisterInfo {
+
+	static final String XML_ELEMENT_NAME = "ContextRegisterInfo";
+
 	String contextRegister;//the context register
-	String value;//the value it assumes (needed because a BigInteger will not serialize to xml)
-	BigInteger valueAsBigInteger;//the value it assumes
+	BigInteger value;//the value it assumes
 
 	/**
 	 * Default constructor (used by XMLEncoder)
@@ -56,21 +60,11 @@
 	}
 
 	/**
-	 * Returns the value associated with this {@link ContextRegisterInfo} object as a 
-	 * {@link BigInteger}.
-	 * @return
+	 * Sets the value associated with this {@link ContextRegisterInfo} object
+	 * @param value
 	 */
-	public BigInteger getValueAsBigInteger() {
-		return valueAsBigInteger;
-	}
-
-	/**
-	 * Sets the value associated with this {@link ContextRegisterInfo} object
-	 * @param valueAsBigInteger
-	 */
-	public void setValue(BigInteger valueAsBigInteger) {
-		this.valueAsBigInteger = valueAsBigInteger;
-		this.value = valueAsBigInteger.toString();
+	public void setValue(BigInteger value) {
+		this.value = value;
 
 	}
 
@@ -79,17 +73,8 @@
 	 * {@link String}.
 	 * @return
 	 */
-	public String getValue() {
+	public BigInteger getValue() {
 		return value;
-	}
-
-	/**
-	 * Sets the value associated with this {@link ContextRegisterInfo} object
-	 * @param value
-	 */
-	public void setValue(String value) {
-		this.value = value;
-		this.valueAsBigInteger = new BigInteger(value);
 	}
 
 	@Override
@@ -133,4 +118,38 @@
 		hashCode = 31 * hashCode + value.hashCode();
 		return hashCode;
 	}
+
+	/**
+	 * Creates a {@link ContextRegisterInfo} object using data in the supplied XML node.
+	 * 
+	 * @param ele xml Element
+	 * @return new {@link ContextRegisterInfo} object, never null
+	 */
+	public static ContextRegisterInfo fromXml(Element ele) {
+
+		String contextRegister = ele.getAttributeValue("contextRegister");
+		String value = ele.getAttributeValue("value");
+
+		ContextRegisterInfo result = new ContextRegisterInfo();
+		result.setContextRegister(contextRegister);
+		result.setValue(value != null ? new BigInteger(value) : null);
+
+		return result;
+	}
+
+	/**
+	 * Converts this object into XML
+	 * 
+	 * @return new jdom Element
+	 */
+	public Element toXml() {
+
+		Element e = new Element(XML_ELEMENT_NAME);
+		e.setAttribute("contextRegister", contextRegister);
+		if (value != null) {
+			e.setAttribute("value", value.toString());
+		}
+
+		return e;
+	}
 }
```
