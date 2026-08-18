# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4362_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4362_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 39-79 of the vulnerable file.

import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;

import javax.xml.transform.Source;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.iso_relax.verifier.Schema;
import org.iso_relax.verifier.Verifier;
import org.iso_relax.verifier.VerifierConfigurationException;
import org.iso_relax.verifier.VerifierFactory;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.anno.JRubyClass;
import org.jruby.runtime.ThreadContext;
import org.w3c.dom.Document;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

/**
 * Class for Nokogiri::XML::RelaxNG
 * 
 * @author sergio
 * @author Yoko Harada <yokolet@gmail.com>
 */
@JRubyClass(name="Nokogiri::XML::RelaxNG", parent="Nokogiri::XML::Schema")
public class XmlRelaxng extends XmlSchema {
    private Verifier verifier;

    public XmlRelaxng(Ruby ruby, RubyClass klazz) {
        super(ruby, klazz);
    }
    
    private void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,7 @@
 import org.jruby.RubyClass;
 import org.jruby.anno.JRubyClass;
 import org.jruby.runtime.ThreadContext;
+import org.jruby.runtime.builtin.IRubyObject;
 import org.w3c.dom.Document;
 import org.xml.sax.ErrorHandler;
 import org.xml.sax.SAXException;
@@ -78,11 +79,17 @@
         this.verifier = verifier;
     }
     
-    static XmlSchema createSchemaInstance(ThreadContext context, RubyClass klazz, Source source) {
+    static XmlSchema createSchemaInstance(ThreadContext context, RubyClass klazz, Source source, IRubyObject parseOptions) {
         Ruby runtime = context.getRuntime();
         XmlRelaxng xmlRelaxng = (XmlRelaxng) NokogiriService.XML_RELAXNG_ALLOCATOR.allocate(runtime, klazz);
+
+        if (parseOptions == null) {
+            parseOptions = defaultParseOptions(context.getRuntime());
+        }
+
         xmlRelaxng.setInstanceVariable("@errors", runtime.newEmptyArray());
-        
+        xmlRelaxng.setInstanceVariable("@parse_options", parseOptions);
+
         try {
             Schema schema = xmlRelaxng.getSchema(source, context);
             xmlRelaxng.setVerifier(schema.newVerifier());
```
