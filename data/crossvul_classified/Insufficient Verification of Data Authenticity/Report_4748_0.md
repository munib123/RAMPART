# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in cpp
**Pair ID:** 4748_0
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4748_0`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```cpp
Lines 357-397 of the vulnerable file.

  sxe->iter.data = data;
  return count;
}

static xmlNodePtr php_sxe_get_first_node(SimpleXMLElement* sxe,
                                         xmlNodePtr node) {
  if (sxe && sxe->iter.type != SXE_ITER_NONE) {
    php_sxe_reset_iterator(sxe, true);
    xmlNodePtr retnode = nullptr;
    if (!sxe->iter.data.isNull()) {
      assert(sxe->iter.data->instanceof(SimpleXMLElement_classof()));
      retnode = Native::data<SimpleXMLElement>(sxe->iter.data.get())->nodep();
    }
    return retnode;
  } else {
    return node;
  }
}

xmlNodePtr SimpleXMLElement_exportNode(const Object& sxe) {
  assert(sxe->instanceof(SimpleXMLElement_classof()));
  auto data = Native::data<SimpleXMLElement>(sxe.get());
  return php_sxe_get_first_node(data, data->nodep());
}

static Object sxe_prop_dim_read(SimpleXMLElement* sxe, const Variant& member,
                                bool elements, bool attribs) {
  xmlNodePtr node = sxe->nodep();

  String name = "";
  if (member.isNull() || member.isInteger()) {
    if (sxe->iter.type != SXE_ITER_ATTRLIST) {
      attribs = false;
      elements = true;
    } else if (member.isNull()) {
      /* This happens when the user did: $sxe[]->foo = $value */
      raise_error("Cannot create unnamed attribute");
      return Object{};
    }
  } else {
    name = member.toString();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -374,7 +374,7 @@
 }
 
 xmlNodePtr SimpleXMLElement_exportNode(const Object& sxe) {
-  assert(sxe->instanceof(SimpleXMLElement_classof()));
+  if (!sxe->instanceof(SimpleXMLElement_classof())) return nullptr;
   auto data = Native::data<SimpleXMLElement>(sxe.get());
   return php_sxe_get_first_node(data, data->nodep());
 }
@@ -1166,9 +1166,15 @@
   return cls;
 }
 
+const StaticString s_DOMNode("DOMNode");
+
 static Variant HHVM_FUNCTION(simplexml_import_dom,
-  const Object& node,
-  const String& class_name /* = "SimpleXMLElement" */) {
+                             const Object& node,
+                             const String& class_name) {
+  if (!node->instanceof(s_DOMNode)) {
+    raise_warning("Invalid Nodetype to import");
+    return init_null();
+  }
   auto domnode = Native::data<DOMNode>(node);
   xmlNodePtr nodep = domnode->nodep();
 
```
