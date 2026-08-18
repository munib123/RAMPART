# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 3875_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3875_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 90-130 of the vulnerable file.


    public static ProcessingInstruction createProcessingInstruction(String pi,
            Map<String, String> data) {
        return getDocumentFactory().createProcessingInstruction(pi, data);
    }

    public static QName createQName(String localName, Namespace namespace) {
        return getDocumentFactory().createQName(localName, namespace);
    }

    public static QName createQName(String localName) {
        return getDocumentFactory().createQName(localName);
    }

    /**
     * <p>
     * <code>createXPath</code> parses an XPath expression and creates a new
     * XPath <code>XPath</code> instance using the singleton {@link
     * DocumentFactory}.
     * </p>
     * 
     * @param xpathExpression
     *            is the XPath expression to create
     * 
     * @return a new <code>XPath</code> instance
     * 
     * @throws InvalidXPathException
     *             if the XPath expression is invalid
     */
    public static XPath createXPath(String xpathExpression)
            throws InvalidXPathException {
        return getDocumentFactory().createXPath(xpathExpression);
    }

    /**
     * <p>
     * <code>createXPath</code> parses an XPath expression and creates a new
     * XPath <code>XPath</code> instance using the singleton {@link
     * DocumentFactory}.
     * </p>
     * 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,12 +107,12 @@
      * XPath <code>XPath</code> instance using the singleton {@link
      * DocumentFactory}.
      * </p>
-     * 
+     *
      * @param xpathExpression
      *            is the XPath expression to create
-     * 
+     *
      * @return a new <code>XPath</code> instance
-     * 
+     *
      * @throws InvalidXPathException
      *             if the XPath expression is invalid
      */
@@ -127,14 +127,14 @@
      * XPath <code>XPath</code> instance using the singleton {@link
      * DocumentFactory}.
      * </p>
-     * 
+     *
      * @param xpathExpression
      *            is the XPath expression to create
      * @param context
      *            is the variable context to use when evaluating the XPath
-     * 
+     *
      * @return a new <code>XPath</code> instance
-     * 
+     *
      * @throws InvalidXPathException
      *             if the XPath expression is invalid
      */
@@ -150,10 +150,10 @@
      * filter expressions occur within XPath expressions such as
      * <code>self::node()[ filterExpression ]</code>
      * </p>
-     * 
+     *
      * @param xpathFilterExpression
      *            is the XPath filter expression to create
-     * 
+     *
      * @return a new <code>NodeFilter</code> instance
      */
     public static NodeFilter createXPathFilter(String xpathFilterExpression) {
@@ -166,10 +166,10 @@
      * an XSLT style {@link Pattern}instance which can then be used in an XSLT
      * processing model.
      * </p>
-     * 
+     *
      * @param xpathPattern
      *            is the XPath pattern expression to create
-     * 
+     *
      * @return a new <code>Pattern</code> instance
      */
     public static Pattern createPattern(String xpathPattern) {
@@ -182,12 +182,12 @@
      * {@link List}of {@link Node}instances appending all the results together
      * into a single list.
      * </p>
-     * 
+     *
      * @param xpathFilterExpression
      *            is the XPath filter expression to evaluate
      * @param nodes
      *            is the list of nodes on which to evalute the XPath
-     * 
+     *
      * @return the results of all the XPath evaluations as a single list
      */
     public static List<Node> selectNodes(String xpathFilterExpression, List<Node> nodes) {
@@ -202,12 +202,12 @@
      * {@link List}of {@link Node}instances appending all the results together
      * into a single list.
      * </p>
-     * 
+     *
      * @param xpathFilterExpression
      *            is the XPath filter expression to evaluate
      * @param node
      *            is the Node on which to evalute the XPath
-     * 
+     *
      * @return the results of all the XPath evaluations as a single list
      */
     public static List<Node> selectNodes(String xpathFilterExpression, Node node) {
@@ -221,7 +221,7 @@
      * <code>sort</code> sorts the given List of Nodes using an XPath
      * expression as a {@link java.util.Comparator}.
      * </p>
-     * 
+     *
      * @param list
      *            is the list of Nodes to sort
      * @param xpathExpression
@@ -238,7 +238,7 @@
      * expression as a {@link java.util.Comparator}and optionally removing
      * duplicates.
      * </p>
-     * 
+     *
      * @param list
      *            is the list of Nodes to sort
      * @param expression
@@ -259,24 +259,17 @@
      * </p>
      *
      * Loading external DTD and entities is disabled (if it is possible) for security reasons.
-     * 
+     *
      * @param text
      *            the XML text to be parsed
-     * 
+     *
      * @return a newly parsed Document
-     * 
+     *
      * @throws DocumentException
      *             if the document could not be parsed
      */
     public static Document parseText(String text) throws DocumentException {
-        SAXReader reader = new SAXReader();
-        try {
-            reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
-            reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
-            reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
-        } catch (SAXException e) {
-            //Parse with external resources downloading allowed.
-        }
+        SAXReader reader = SAXReader.createDefault();
 
         String encoding = getEncoding(text);
 
@@ -330,14 +323,14 @@
      * get the first child &lt;a&gt; element, which would be created if it did
      * not exist, then the next child &lt;b&gt; and so on until finally a
      * &lt;c&gt; element is returned.
-     * 
+     *
      * @param source
      *            is the Element or Document to start navigating from
      * @param path
      *            is a simple path expression, seperated by '/' which denotes
      *            the path from the source to the resulting element such as
      *            a/b/c
-     * 
+     *
      * @return the first Element on the given path which either already existed
      *         on the path or were created by this method.
      */
@@ -386,24 +379,24 @@
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
@@ -415,6 +408,6 @@
  * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  * POSSIBILITY OF SUCH DAMAGE.
- * 
+ *
  * Copyright 2001-2005 (C) MetaStuff, Ltd. All Rights Reserved.
  */
```
