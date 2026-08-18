# CrossVul Fix Pair: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') in python
**Pair ID:** 4531_2
**Vulnerability Class:** Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
**CWE:** CWE-776
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4531_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') - If the DTD contains a large number of nested or recursive entities, this can lead to explosive growth of data when parsed, causing a denial of service.

## Vulnerable Code
```python
Lines 1-35 of the vulnerable file.

# -*- coding: utf-8 -*-
'''
    feedgen.ext.geo_entry
    ~~~~~~~~~~~~~~~~~~~

    Extends the FeedGenerator to produce Simple GeoRSS feeds.

    :copyright: 2017, Bob Breznak <bob.breznak@gmail.com>

    :license: FreeBSD and LGPL, see license.* for more details.
'''
import numbers
import warnings

from lxml import etree
from feedgen.ext.base import BaseEntryExtension


class GeoRSSPolygonInteriorWarning(Warning):
    """
    Simple placeholder for warning about ignored polygon interiors.

    Stores the original geom on a ``geom`` attribute (if required warnings are
    raised as errors).
    """

    def __init__(self, geom, *args, **kwargs):
        self.geom = geom
        super(GeoRSSPolygonInteriorWarning, self).__init__(*args, **kwargs)

    def __str__(self):
        return '{:d} interiors of polygon ignored'.format(
            len(self.geom.__geo_interface__['coordinates']) - 1
        )  # ignore exterior in count

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,8 +12,8 @@
 import numbers
 import warnings
 
-from lxml import etree
 from feedgen.ext.base import BaseEntryExtension
+from feedgen.util import xml_elem
 
 
 class GeoRSSPolygonInteriorWarning(Warning):
@@ -86,49 +86,43 @@
         GEO_NS = 'http://www.georss.org/georss'
 
         if self.__point:
-            point = etree.SubElement(entry, '{%s}point' % GEO_NS)
+            point = xml_elem('{%s}point' % GEO_NS, entry)
             point.text = self.__point
 
         if self.__line:
-            line = etree.SubElement(entry, '{%s}line' % GEO_NS)
+            line = xml_elem('{%s}line' % GEO_NS, entry)
             line.text = self.__line
 
         if self.__polygon:
-            polygon = etree.SubElement(entry, '{%s}polygon' % GEO_NS)
+            polygon = xml_elem('{%s}polygon' % GEO_NS, entry)
             polygon.text = self.__polygon
 
         if self.__box:
-            box = etree.SubElement(entry, '{%s}box' % GEO_NS)
+            box = xml_elem('{%s}box' % GEO_NS, entry)
             box.text = self.__box
 
         if self.__featuretypetag:
-            featuretypetag = etree.SubElement(
-                entry,
-                '{%s}featuretypetag' % GEO_NS
-            )
+            featuretypetag = xml_elem('{%s}featuretypetag' % GEO_NS, entry)
             featuretypetag.text = self.__featuretypetag
 
         if self.__relationshiptag:
-            relationshiptag = etree.SubElement(
-                entry,
-                '{%s}relationshiptag' % GEO_NS
-            )
+            relationshiptag = xml_elem('{%s}relationshiptag' % GEO_NS, entry)
             relationshiptag.text = self.__relationshiptag
 
         if self.__featurename:
-            featurename = etree.SubElement(entry, '{%s}featurename' % GEO_NS)
+            featurename = xml_elem('{%s}featurename' % GEO_NS, entry)
             featurename.text = self.__featurename
 
         if self.__elev:
-            elevation = etree.SubElement(entry, '{%s}elev' % GEO_NS)
+            elevation = xml_elem('{%s}elev' % GEO_NS, entry)
             elevation.text = str(self.__elev)
 
         if self.__floor:
-            floor = etree.SubElement(entry, '{%s}floor' % GEO_NS)
+            floor = xml_elem('{%s}floor' % GEO_NS, entry)
             floor.text = str(self.__floor)
 
         if self.__radius:
-            radius = etree.SubElement(entry, '{%s}radius' % GEO_NS)
+            radius = xml_elem('{%s}radius' % GEO_NS, entry)
             radius.text = str(self.__radius)
 
         return entry
```
