# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 4362_1
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4362_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 89-129 of the vulnerable file.

     *
     * @return a clone of this object
     */
    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }

    private Schema getSchema(Source source, String currentDir, String scriptFileName, SchemaErrorHandler error_handler) throws SAXException {
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        SchemaResourceResolver resourceResolver = new SchemaResourceResolver(currentDir, scriptFileName, null, error_handler);
        schemaFactory.setResourceResolver(resourceResolver);
        schemaFactory.setErrorHandler(error_handler);
        return schemaFactory.newSchema(source);
    }

    private void setValidator(Validator validator) {
        this.validator = validator;
    }

    static XmlSchema createSchemaInstance(ThreadContext context, RubyClass klazz, Source source) {
        Ruby runtime = context.getRuntime();
        XmlSchema xmlSchema = (XmlSchema) NokogiriService.XML_SCHEMA_ALLOCATOR.allocate(runtime, klazz);
        xmlSchema.setInstanceVariable("@errors", runtime.newEmptyArray());

        try {
            SchemaErrorHandler error_handler = new SchemaErrorHandler(context.getRuntime(), (RubyArray)xmlSchema.getInstanceVariable("@errors"));
            Schema schema = xmlSchema.getSchema(source, context.getRuntime().getCurrentDirectory(), context.getRuntime().getInstanceConfig().getScriptFileName(), error_handler);
            xmlSchema.setValidator(schema.newValidator());
            return xmlSchema;
        } catch (SAXException ex) {
            throw context.getRuntime().newRuntimeError("Could not parse document: " + ex.getMessage());
        }
    }

    /*
     * call-seq:
     *  from_document(doc)
     *
     * Create a new Schema from the Nokogiri::XML::Document +doc+
     */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,10 +106,16 @@
         this.validator = validator;
     }
 
-    static XmlSchema createSchemaInstance(ThreadContext context, RubyClass klazz, Source source) {
+    static XmlSchema createSchemaInstance(ThreadContext context, RubyClass klazz, Source source, IRubyObject parseOptions) {
         Ruby runtime = context.getRuntime();
         XmlSchema xmlSchema = (XmlSchema) NokogiriService.XML_SCHEMA_ALLOCATOR.allocate(runtime, klazz);
+
+        if (parseOptions == null) {
+            parseOptions = defaultParseOptions(context.getRuntime());
+        }
+
         xmlSchema.setInstanceVariable("@errors", runtime.newEmptyArray());
+        xmlSchema.setInstanceVariable("@parse_options", parseOptions);
 
         try {
             SchemaErrorHandler error_handler = new SchemaErrorHandler(context.getRuntime(), (RubyArray)xmlSchema.getInstanceVariable("@errors"));
@@ -121,14 +127,24 @@
         }
     }
 
+    protected static IRubyObject defaultParseOptions(Ruby runtime) {
+        return ((RubyClass)runtime.getClassFromPath("Nokogiri::XML::ParseOptions")).getConstant("DEFAULT_SCHEMA");
+    }
+
     /*
      * call-seq:
      *  from_document(doc)
      *
      * Create a new Schema from the Nokogiri::XML::Document +doc+
      */
-    @JRubyMethod(meta=true)
-    public static IRubyObject from_document(ThreadContext context, IRubyObject klazz, IRubyObject document) {
+    @JRubyMethod(meta=true, required=1, optional=1)
+    public static IRubyObject from_document(ThreadContext context, IRubyObject klazz, IRubyObject[] args) {
+        IRubyObject document = args[0];
+        IRubyObject parseOptions = null;
+        if (args.length > 1) {
+            parseOptions = args[1];
+        }
+
         XmlDocument doc = ((XmlDocument) ((XmlNode) document).document(context));
 
         RubyArray errors = (RubyArray) doc.getInstanceVariable("@errors");
@@ -144,23 +160,28 @@
             source.setSystemId(uri.convertToString().asJavaString());
         }
 
-        return getSchema(context, (RubyClass)klazz, source);
-    }
-
-    private static IRubyObject getSchema(ThreadContext context, RubyClass klazz, Source source) {
+        return getSchema(context, (RubyClass)klazz, source, parseOptions);
+    }
+
+    @JRubyMethod(meta=true, required=1, optional=1)
+    public static IRubyObject read_memory(ThreadContext context, IRubyObject klazz, IRubyObject[] args) {
+        IRubyObject content = args[0];
+        IRubyObject parseOptions = null;
+        if (args.length > 1) {
+            parseOptions = args[1];
+        }
+        String data = content.convertToString().asJavaString();
+        return getSchema(context, (RubyClass) klazz, new StreamSource(new StringReader(data)), parseOptions);
+    }
+
+    private static IRubyObject getSchema(ThreadContext context, RubyClass klazz, Source source, IRubyObject parseOptions) {
         String moduleName = klazz.getName();
         if ("Nokogiri::XML::Schema".equals(moduleName)) {
-            return XmlSchema.createSchemaInstance(context, klazz, source);
+            return XmlSchema.createSchemaInstance(context, klazz, source, parseOptions);
         } else if ("Nokogiri::XML::RelaxNG".equals(moduleName)) {
-            return XmlRelaxng.createSchemaInstance(context, klazz, source);
+            return XmlRelaxng.createSchemaInstance(context, klazz, source, parseOptions);
         }
         return context.getRuntime().getNil();
-    }
-
-    @JRubyMethod(meta=true)
-    public static IRubyObject read_memory(ThreadContext context, IRubyObject klazz, IRubyObject content) {
-        String data = content.convertToString().asJavaString();
-        return getSchema(context, (RubyClass) klazz, new StreamSource(new StringReader(data)));
     }
 
     @JRubyMethod(visibility=Visibility.PRIVATE)
```
