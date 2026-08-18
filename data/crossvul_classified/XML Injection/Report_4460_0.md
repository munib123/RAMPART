# CrossVul Fix Pair: XML Injection (aka Blind XPath Injection) in python
**Pair ID:** 4460_0
**Vulnerability Class:** XML Injection
**CWE:** CWE-91
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4460_0`)

## Vulnerability Information & PoC

## Description
XML Injection (aka Blind XPath Injection) - Within XML, special elements could include reserved words or characters such as <, >, , and &, which could then be used to add new data or modify XML syntax.

## Vulnerable Code
```python
Lines 116-156 of the vulnerable file.

        | ('1', '3') | 'a' |
        +------------+-----+
        | '2'        | 'b' |
        +------------+-----+
        | '2'        | 'c' |
        +------------+-----+

    If `lxml <http://lxml.de/>`_ is installed, full XPath expressions can be
    used.

    Note that the implementation is currently **not** streaming, i.e.,
    the whole document is loaded into memory.

    If multiple elements match a given field, all values are reported as a
    tuple.

    If there is more than one element name used for row values, a tuple
    or list of paths can be provided, e.g.,
    ``fromxml('example.html', './/tr', ('th', 'td'))``.

    """

    source = read_source_from_arg(source)
    return XmlView(source, *args, **kwargs)


class XmlView(Table):

    def __init__(self, source, *args, **kwargs):
        self.source = source
        self.args = args
        if len(args) == 2 and isinstance(args[1], (string_types, tuple, list)):
            self.rmatch = args[0]
            self.vmatch = args[1]
            self.vdict = None
            self.attr = None
        elif len(args) == 2 and isinstance(args[1], dict):
            self.rmatch = args[0]
            self.vmatch = None
            self.vdict = args[1]
            self.attr = None
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,6 +132,9 @@
     If there is more than one element name used for row values, a tuple
     or list of paths can be provided, e.g.,
     ``fromxml('example.html', './/tr', ('th', 'td'))``.
+
+    Optionally a custom parser can be provided, e.g.,
+    ``etl.fromxml('example1.xml', 'tr', 'td', parser=my_parser)``.
 
     """
 
@@ -162,14 +165,15 @@
         else:
             assert False, 'bad parameters'
         self.missing = kwargs.get('missing', None)
+        self.user_parser = kwargs.get('parser', None)
 
     def __iter__(self):
         vmatch = self.vmatch
         vdict = self.vdict
 
         with self.source.open('rb') as xmlf:
-
-            tree = etree.parse(xmlf)
+            parser2 = _create_xml_parser(self.user_parser)
+            tree = etree.parse(xmlf, parser=parser2)
             if not hasattr(tree, 'iterfind'):
                 # Python 2.6 compatibility
                 tree.iterfind = tree.findall
@@ -219,6 +223,20 @@
                                 for f in flds)
 
 
+def _create_xml_parser(user_parser):
+    if user_parser is not None:
+        return user_parser
+    try:
+        # Default lxml parser.
+        # This will throw an error if parser is not set and lxml could not be imported
+        # because Python's built XML parser doesn't like the `resolve_entities` kwarg.
+        # return etree.XMLParser(resolve_entities=False)
+        return etree.XMLParser(resolve_entities=False)
+    except TypeError:
+        # lxml not available
+        return None
+
+
 def element_text_getter(missing):
     def _get(v):
         if len(v) > 1:
```
