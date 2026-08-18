# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in java
**Pair ID:** 44_1
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `44_1`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```java
Lines 1-34 of the vulnerable file.

/*
 * Copyright 2001-2005 (C) MetaStuff, Ltd. All Rights Reserved.
 *
 * This software is open source.
 * See the bottom of this file for the licence.
 */

package org.dom4j;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import org.dom4j.tree.QNameCache;
import org.dom4j.util.SingletonStrategy;

/**
 * <code>QName</code> represents a qualified name value of an XML element or
 * attribute. It consists of a local name and a {@link Namespace}instance. This
 * object is immutable.
 *
 * @author <a href="mailto:jstrachan@apache.org">James Strachan </a>
 */
public class QName implements Serializable {
    /** The Singleton instance */
    private static SingletonStrategy<QNameCache> singleton = null;

    static {
        try {
            String defaultSingletonClass = "org.dom4j.util.SimpleSingleton";
            Class<SingletonStrategy> clazz = null;
            try {
                String singletonClass = defaultSingletonClass;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,6 +11,7 @@
 import java.io.ObjectInputStream;
 import java.io.ObjectOutputStream;
 import java.io.Serializable;
+import java.util.regex.Pattern;
 
 import org.dom4j.tree.QNameCache;
 import org.dom4j.util.SingletonStrategy;
@@ -21,10 +22,85 @@
  * object is immutable.
  *
  * @author <a href="mailto:jstrachan@apache.org">James Strachan </a>
+ * @author Filip Jirsák
  */
 public class QName implements Serializable {
     /** The Singleton instance */
     private static SingletonStrategy<QNameCache> singleton = null;
+
+    /**
+     * {@code NameStartChar} without colon.
+     *
+     * <pre>NameStartChar	::=	":" | [A-Z] | "_" | [a-z] | [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] | [#x370-#x37D] | [#x37F-#x1FFF] | [#x200C-#x200D] | [#x2070-#x218F] | [#x2C00-#x2FEF] | [#x3001-#xD7FF] | [#xF900-#xFDCF] | [#xFDF0-#xFFFD] | [#x10000-#xEFFFF]</pre>
+     *
+     * @see <a href="https://www.w3.org/TR/xml/#sec-common-syn">XML 1.0 – 2.3 Common Syntactic Constructs</a>
+     * @see <a href="https://www.w3.org/TR/2006/REC-xml11-20060816/#sec-common-syn">XML 1.1 – 2.3 Common Syntactic Constructs</a>
+     */
+    private static final String NAME_START_CHAR = "_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD";
+
+    /**
+     * {@code NameChar} without colon.
+     *
+     * <pre>NameChar	::=	NameStartChar | "-" | "." | [0-9] | #xB7 | [#x0300-#x036F] | [#x203F-#x2040]</pre>
+     *
+     * @see <a href="https://www.w3.org/TR/xml/#sec-common-syn">XML 1.0 – 2.3 Common Syntactic Constructs</a>
+     * @see <a href="https://www.w3.org/TR/2006/REC-xml11-20060816/#sec-common-syn">XML 1.1 – 2.3 Common Syntactic Constructs</a>
+     */
+    private static final String NAME_CHAR = NAME_START_CHAR + "-.0-9\u00B7\u0300-\u036F\u203F-\u2040";
+
+    /**
+     * {@code NCName}
+     *
+     * <pre>
+     * NCName		::=	NCNameStartChar NCNameChar*	(An XML Name, minus the ":")
+     * NCNameChar	::=	NameChar -':'
+     * NCNameStartChar	::=	NameStartChar -':'
+     * </pre>
+     *
+     * @see <a href="https://www.w3.org/TR/xml-names/#ns-qualnames">Namespaces in XML 1.0 – 4 Qualified Names</a>
+     * @see <a href="https://www.w3.org/TR/2006/REC-xml-names11-20060816/#ns-qualnames">Namespaces in XML 1.1 – 4 Qualified Names</a>
+     */
+    private static final String NCNAME = "["+NAME_START_CHAR+"]["+NAME_CHAR+"]*";
+
+    /**
+     * Regular expression for {@code Name} (with colon).
+     *
+     * <pre>Name	::=	NameStartChar (NameChar)*</pre>
+     *
+     * @see <a href="https://www.w3.org/TR/xml/#sec-common-syn">XML 1.0 – 2.3 Common Syntactic Constructs</a>
+     * @see <a href="https://www.w3.org/TR/2006/REC-xml11-20060816/#sec-common-syn">XML 1.1 – 2.3 Common Syntactic Constructs</a>
+     */
+    private static final Pattern RE_NAME = Pattern.compile("[:"+NAME_START_CHAR+"][:"+NAME_CHAR+"]*");
+
+    /**
+     * Regular expression for {@code NCName}.
+     *
+     * <pre>
+     * NCName		::=	NCNameStartChar NCNameChar*	(An XML Name, minus the ":")
+     * NCNameChar	::=	NameChar -':'
+     * NCNameStartChar	::=	NameStartChar -':'
+     * </pre>
+     *
+     * @see <a href="https://www.w3.org/TR/xml-names/#ns-qualnames">Namespaces in XML 1.0 – 4 Qualified Names</a>
+     * @see <a href="https://www.w3.org/TR/2006/REC-xml-names11-20060816/#ns-qualnames">Namespaces in XML 1.1 – 4 Qualified Names</a>
+     */
+    private static final Pattern RE_NCNAME = Pattern.compile(NCNAME);
+
+    /**
+     * Regular expression for {@code QName}.
+     *
+     * <pre>
+     * QName		::=	PrefixedName | UnprefixedName
+     * PrefixedName	::=	Prefix ':' LocalPart
+     * UnprefixedName	::=	LocalPart
+     * Prefix		::=	NCName
+     * LocalPart	::=	NCName
+     * </pre>
+     *
+     * @see <a href="https://www.w3.org/TR/xml-names/#ns-qualnames">Namespaces in XML 1.0 – 4 Qualified Names</a>
+     * @see <a href="https://www.w3.org/TR/2006/REC-xml-names11-20060816/#ns-qualnames">Namespaces in XML 1.1 – 4 Qualified Names</a>
+     */
+    private static final Pattern RE_QNAME = Pattern.compile("(?:"+NCNAME+":)?"+NCNAME);
 
     static {
         try {
@@ -71,6 +147,11 @@
         this.name = (name == null) ? "" : name;
         this.namespace = (namespace == null) ? Namespace.NO_NAMESPACE
                 : namespace;
+        if (this.namespace.equals(Namespace.NO_NAMESPACE)) {
+            validateName(this.name);
+        } else {
+            validateNCName(this.name);
+        }
     }
 
     public QName(String name, Namespace namespace, String qualifiedName) {
@@ -78,6 +159,8 @@
         this.qualifiedName = qualifiedName;
         this.namespace = (namespace == null) ? Namespace.NO_NAMESPACE
                 : namespace;
+        validateNCName(this.name);
+        validateQName(this.qualifiedName);
     }
 
     public static QName get(String name) {
@@ -250,6 +333,24 @@
     private static QNameCache getCache() {
         QNameCache cache = singleton.instance();
         return cache;
+    }
+
+    private static void validateName(String name) {
+        if (!RE_NAME.matcher(name).matches()) {
+            throw new IllegalArgumentException(String.format("Illegal character in name: '%s'.", name));
+        }
+    }
+
+    protected static void validateNCName(String ncname) {
+        if (!RE_NCNAME.matcher(ncname).matches()) {
+            throw new IllegalArgumentException(String.format("Illegal character in local name: '%s'.", ncname));
+        }
+    }
+
+    private static void validateQName(String qname) {
+        if (!RE_QNAME.matcher(qname).matches()) {
+            throw new IllegalArgumentException(String.format("Illegal character in qualified name: '%s'.", qname));
+        }
     }
 }
 
```
