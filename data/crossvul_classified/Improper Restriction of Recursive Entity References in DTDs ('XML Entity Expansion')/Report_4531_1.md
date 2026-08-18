# CrossVul Fix Pair: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') in python
**Pair ID:** 4531_1
**Vulnerability Class:** Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
**CWE:** CWE-776
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4531_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') - If the DTD contains a large number of nested or recursive entities, this can lead to explosive growth of data when parsed, causing a denial of service.

## Vulnerable Code
```python
Lines 1-37 of the vulnerable file.

# -*- coding: utf-8 -*-
'''
    feedgen.ext.dc
    ~~~~~~~~~~~~~~~~~~~

    Extends the FeedGenerator to add Dubline Core Elements to the feeds.

    Descriptions partly taken from
    http://dublincore.org/documents/dcmi-terms/#elements-coverage

    :copyright: 2013-2017, Lars Kiesow <lkiesow@uos.de>

    :license: FreeBSD and LGPL, see license.* for more details.
'''

from lxml import etree

from feedgen.ext.base import BaseExtension


class DcBaseExtension(BaseExtension):
    '''Dublin Core Elements extension for podcasts.
    '''

    def __init__(self):
        # http://dublincore.org/documents/usageguide/elements.shtml
        # http://dublincore.org/documents/dces/
        # http://dublincore.org/documents/dcmi-terms/
        self._dcelem_contributor = None
        self._dcelem_coverage = None
        self._dcelem_creator = None
        self._dcelem_date = None
        self._dcelem_description = None
        self._dcelem_format = None
        self._dcelem_identifier = None
        self._dcelem_language = None
        self._dcelem_publisher = None
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,9 +13,8 @@
     :license: FreeBSD and LGPL, see license.* for more details.
 '''
 
-from lxml import etree
-
 from feedgen.ext.base import BaseExtension
+from feedgen.util import xml_elem
 
 
 class DcBaseExtension(BaseExtension):
@@ -45,10 +44,10 @@
     def extend_ns(self):
         return {'dc': 'http://purl.org/dc/elements/1.1/'}
 
-    def _extend_xml(self, xml_elem):
-        '''Extend xml_elem with set DC fields.
-
-        :param xml_elem: etree element
+    def _extend_xml(self, xml_element):
+        '''Extend xml_element with set DC fields.
+
+        :param xml_element: etree element
         '''
         DCELEMENTS_NS = 'http://purl.org/dc/elements/1.1/'
 
@@ -58,8 +57,8 @@
                      'identifier']:
             if hasattr(self, '_dcelem_%s' % elem):
                 for val in getattr(self, '_dcelem_%s' % elem) or []:
-                    node = etree.SubElement(xml_elem,
-                                            '{%s}%s' % (DCELEMENTS_NS, elem))
+                    node = xml_elem('{%s}%s' % (DCELEMENTS_NS, elem),
+                                    xml_element)
                     node.text = val
 
     def extend_atom(self, atom_feed):
```
