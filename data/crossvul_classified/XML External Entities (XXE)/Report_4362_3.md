# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in c
**Pair ID:** 4362_3
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4362_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```c
Lines 76-116 of the vulnerable file.

  xmlSchemaSetValidStructuredErrors(
    valid_ctxt,
    Nokogiri_error_array_pusher,
    (void *)errors
  );
#endif

  xmlSchemaValidateFile(valid_ctxt, filename, 0);

  xmlSchemaFreeValidCtxt(valid_ctxt);

  return errors;
}

/*
 * call-seq:
 *  read_memory(string)
 *
 * Create a new Schema from the contents of +string+
 */
static VALUE read_memory(VALUE klass, VALUE content)
{
  xmlSchemaPtr schema;
  xmlSchemaParserCtxtPtr ctx = xmlSchemaNewMemParserCtxt(
      (const char *)StringValuePtr(content),
      (int)RSTRING_LEN(content)
  );
  VALUE rb_schema;
  VALUE errors = rb_ary_new();
  xmlSetStructuredErrorFunc((void *)errors, Nokogiri_error_array_pusher);

#ifdef HAVE_XMLSCHEMASETPARSERSTRUCTUREDERRORS
  xmlSchemaSetParserStructuredErrors(
    ctx,
    Nokogiri_error_array_pusher,
    (void *)errors
  );
#endif

   schema = xmlSchemaParse(ctx);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,15 +93,26 @@
  *
  * Create a new Schema from the contents of +string+
  */
-static VALUE read_memory(VALUE klass, VALUE content)
-{
-  xmlSchemaPtr schema;
-  xmlSchemaParserCtxtPtr ctx = xmlSchemaNewMemParserCtxt(
-      (const char *)StringValuePtr(content),
-      (int)RSTRING_LEN(content)
-  );
+static VALUE read_memory(int argc, VALUE *argv, VALUE klass)
+{
+  VALUE content;
+  VALUE parse_options;
+  int parse_options_int;
+  xmlSchemaParserCtxtPtr ctx;
+  xmlSchemaPtr schema;
+  VALUE errors;
   VALUE rb_schema;
-  VALUE errors = rb_ary_new();
+  int scanned_args = 0;
+
+  scanned_args = rb_scan_args(argc, argv, "11", &content, &parse_options);
+  if (scanned_args == 1) {
+    parse_options = rb_const_get(rb_const_get(mNokogiriXml, rb_intern("ParseOptions")), rb_intern("DEFAULT_SCHEMA"));
+  }
+  parse_options_int = (int)NUM2INT(rb_funcall(parse_options, rb_intern("to_i"), 0));
+
+  ctx = xmlSchemaNewMemParserCtxt((const char *)StringValuePtr(content), (int)RSTRING_LEN(content));
+
+  errors = rb_ary_new();
   xmlSetStructuredErrorFunc((void *)errors, Nokogiri_error_array_pusher);
 
 #ifdef HAVE_XMLSCHEMASETPARSERSTRUCTUREDERRORS
@@ -109,7 +120,7 @@
     ctx,
     Nokogiri_error_array_pusher,
     (void *)errors
-  );
+    );
 #endif
 
    schema = xmlSchemaParse(ctx);
@@ -129,6 +140,7 @@
 
   rb_schema = Data_Wrap_Struct(klass, 0, dealloc, schema);
   rb_iv_set(rb_schema, "@errors", errors);
+  rb_iv_set(rb_schema, "@parse_options", parse_options);
 
   return rb_schema;
 }
@@ -164,18 +176,27 @@
  *
  * Create a new Schema from the Nokogiri::XML::Document +doc+
  */
-static VALUE from_document(VALUE klass, VALUE document)
-{
+static VALUE from_document(int argc, VALUE *argv, VALUE klass)
+{
+  VALUE document;
+  VALUE parse_options;
+  int parse_options_int;
   xmlDocPtr doc;
   xmlSchemaParserCtxtPtr ctx;
   xmlSchemaPtr schema;
   VALUE errors;
   VALUE rb_schema;
+  int scanned_args = 0;
+
+  scanned_args = rb_scan_args(argc, argv, "11", &document, &parse_options);
 
   Data_Get_Struct(document, xmlDoc, doc);
-
-  /* In case someone passes us a node. ugh. */
-  doc = doc->doc;
+  doc = doc->doc; /* In case someone passes us a node. ugh. */
+
+  if (scanned_args == 1) {
+    parse_options = rb_const_get(rb_const_get(mNokogiriXml, rb_intern("ParseOptions")), rb_intern("DEFAULT_SCHEMA"));
+  }
+  parse_options_int = (int)NUM2INT(rb_funcall(parse_options, rb_intern("to_i"), 0));
 
   if (has_blank_nodes_p(DOC_NODE_CACHE(doc))) {
     rb_raise(rb_eArgError, "Creating a schema from a document that has blank nodes exposed to Ruby is dangerous");
@@ -211,6 +232,7 @@
 
   rb_schema = Data_Wrap_Struct(klass, 0, dealloc, schema);
   rb_iv_set(rb_schema, "@errors", errors);
+  rb_iv_set(rb_schema, "@parse_options", parse_options);
 
   return rb_schema;
 
@@ -226,8 +248,8 @@
 
   cNokogiriXmlSchema = klass;
 
-  rb_define_singleton_method(klass, "read_memory", read_memory, 1);
-  rb_define_singleton_method(klass, "from_document", from_document, 1);
+  rb_define_singleton_method(klass, "read_memory", read_memory, -1);
+  rb_define_singleton_method(klass, "from_document", from_document, -1);
 
   rb_define_private_method(klass, "validate_document", validate_document, 1);
   rb_define_private_method(klass, "validate_file",     validate_file, 1);
```
