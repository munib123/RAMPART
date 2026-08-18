# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in c
**Pair ID:** 4362_2
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4362_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```c
Lines 36-76 of the vulnerable file.

  xmlRelaxNGSetValidStructuredErrors(
    valid_ctxt,
    Nokogiri_error_array_pusher,
    (void *)errors
  );
#endif

  xmlRelaxNGValidateDoc(valid_ctxt, doc);

  xmlRelaxNGFreeValidCtxt(valid_ctxt);

  return errors;
}

/*
 * call-seq:
 *  read_memory(string)
 *
 * Create a new RelaxNG from the contents of +string+
 */
static VALUE read_memory(VALUE klass, VALUE content)
{
  xmlRelaxNGParserCtxtPtr ctx = xmlRelaxNGNewMemParserCtxt(
      (const char *)StringValuePtr(content),
      (int)RSTRING_LEN(content)
  );
  xmlRelaxNGPtr schema;
  VALUE errors = rb_ary_new();
  VALUE rb_schema;

  xmlSetStructuredErrorFunc((void *)errors, Nokogiri_error_array_pusher);

#ifdef HAVE_XMLRELAXNGSETPARSERSTRUCTUREDERRORS
  xmlRelaxNGSetParserStructuredErrors(
    ctx,
    Nokogiri_error_array_pusher,
    (void *)errors
  );
#endif

  schema = xmlRelaxNGParse(ctx);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,16 +53,24 @@
  *
  * Create a new RelaxNG from the contents of +string+
  */
-static VALUE read_memory(VALUE klass, VALUE content)
+static VALUE read_memory(int argc, VALUE *argv, VALUE klass)
 {
-  xmlRelaxNGParserCtxtPtr ctx = xmlRelaxNGNewMemParserCtxt(
-      (const char *)StringValuePtr(content),
-      (int)RSTRING_LEN(content)
-  );
+  VALUE content;
+  VALUE parse_options;
+  xmlRelaxNGParserCtxtPtr ctx;
   xmlRelaxNGPtr schema;
-  VALUE errors = rb_ary_new();
+  VALUE errors;
   VALUE rb_schema;
+  int scanned_args = 0;
 
+  scanned_args = rb_scan_args(argc, argv, "11", &content, &parse_options);
+  if (scanned_args == 1) {
+    parse_options = rb_const_get(rb_const_get(mNokogiriXml, rb_intern("ParseOptions")), rb_intern("DEFAULT_SCHEMA"));
+  }
+
+  ctx = xmlRelaxNGNewMemParserCtxt((const char *)StringValuePtr(content), (int)RSTRING_LEN(content));
+
+  errors = rb_ary_new();
   xmlSetStructuredErrorFunc((void *)errors, Nokogiri_error_array_pusher);
 
 #ifdef HAVE_XMLRELAXNGSETPARSERSTRUCTUREDERRORS
@@ -90,6 +98,7 @@
 
   rb_schema = Data_Wrap_Struct(klass, 0, dealloc, schema);
   rb_iv_set(rb_schema, "@errors", errors);
+  rb_iv_set(rb_schema, "@parse_options", parse_options);
 
   return rb_schema;
 }
@@ -100,18 +109,25 @@
  *
  * Create a new RelaxNG schema from the Nokogiri::XML::Document +doc+
  */
-static VALUE from_document(VALUE klass, VALUE document)
+static VALUE from_document(int argc, VALUE *argv, VALUE klass)
 {
+  VALUE document;
+  VALUE parse_options;
   xmlDocPtr doc;
   xmlRelaxNGParserCtxtPtr ctx;
   xmlRelaxNGPtr schema;
   VALUE errors;
   VALUE rb_schema;
+  int scanned_args = 0;
+
+  scanned_args = rb_scan_args(argc, argv, "11", &document, &parse_options);
 
   Data_Get_Struct(document, xmlDoc, doc);
+  doc = doc->doc; /* In case someone passes us a node. ugh. */
 
-  /* In case someone passes us a node. ugh. */
-  doc = doc->doc;
+  if (scanned_args == 1) {
+    parse_options = rb_const_get(rb_const_get(mNokogiriXml, rb_intern("ParseOptions")), rb_intern("DEFAULT_SCHEMA"));
+  }
 
   ctx = xmlRelaxNGNewDocParserCtxt(doc);
 
@@ -143,6 +159,7 @@
 
   rb_schema = Data_Wrap_Struct(klass, 0, dealloc, schema);
   rb_iv_set(rb_schema, "@errors", errors);
+  rb_iv_set(rb_schema, "@parse_options", parse_options);
 
   return rb_schema;
 }
@@ -156,7 +173,7 @@
 
   cNokogiriXmlRelaxNG = klass;
 
-  rb_define_singleton_method(klass, "read_memory", read_memory, 1);
-  rb_define_singleton_method(klass, "from_document", from_document, 1);
+  rb_define_singleton_method(klass, "read_memory", read_memory, -1);
+  rb_define_singleton_method(klass, "from_document", from_document, -1);
   rb_define_private_method(klass, "validate_document", validate_document, 1);
 }
```
