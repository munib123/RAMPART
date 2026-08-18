# CrossVul Fix Pair: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') in python
**Pair ID:** 4531_3
**Vulnerability Class:** Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
**CWE:** CWE-776
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4531_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') - If the DTD contains a large number of nested or recursive entities, this can lead to explosive growth of data when parsed, causing a denial of service.

## Vulnerable Code
```python
Lines 1-34 of the vulnerable file.

# -*- coding: utf-8 -*-
'''
    feedgen.ext.media
    ~~~~~~~~~~~~~~~~~

    Extends the feedgen to produce media tags.

    :copyright: 2013-2017, Lars Kiesow <lkiesow@uos.de>

    :license: FreeBSD and LGPL, see license.* for more details.
'''

from lxml import etree

from feedgen.ext.base import BaseEntryExtension, BaseExtension
from feedgen.util import ensure_format

MEDIA_NS = 'http://search.yahoo.com/mrss/'


class MediaExtension(BaseExtension):
    '''FeedGenerator extension for torrent feeds.
    '''

    def extend_ns(self):
        return {'media': MEDIA_NS}


class MediaEntryExtension(BaseEntryExtension):
    '''FeedEntry extension for media tags.
    '''

    def __init__(self):
        self.__media_content = []
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,10 +10,8 @@
     :license: FreeBSD and LGPL, see license.* for more details.
 '''
 
-from lxml import etree
-
 from feedgen.ext.base import BaseEntryExtension, BaseExtension
-from feedgen.util import ensure_format
+from feedgen.util import ensure_format, xml_elem
 
 MEDIA_NS = 'http://search.yahoo.com/mrss/'
 
@@ -45,10 +43,10 @@
             # Define current media:group
             group = groups.get(media_content.get('group'))
             if group is None:
-                group = etree.SubElement(entry, '{%s}group' % MEDIA_NS)
+                group = xml_elem('{%s}group' % MEDIA_NS, entry)
                 groups[media_content.get('group')] = group
             # Add content
-            content = etree.SubElement(group, '{%s}content' % MEDIA_NS)
+            content = xml_elem('{%s}content' % MEDIA_NS, group)
             for attr in ('url', 'fileSize', 'type', 'medium', 'isDefault',
                          'expression', 'bitrate', 'framerate', 'samplingrate',
                          'channels', 'duration', 'height', 'width', 'lang'):
@@ -59,10 +57,10 @@
             # Define current media:group
             group = groups.get(media_thumbnail.get('group'))
             if group is None:
-                group = etree.SubElement(entry, '{%s}group' % MEDIA_NS)
+                group = xml_elem('{%s}group' % MEDIA_NS, entry)
                 groups[media_thumbnail.get('group')] = group
             # Add thumbnails
-            thumbnail = etree.SubElement(group, '{%s}thumbnail' % MEDIA_NS)
+            thumbnail = xml_elem('{%s}thumbnail' % MEDIA_NS, group)
             for attr in ('url', 'height', 'width', 'time'):
                 if media_thumbnail.get(attr):
                     thumbnail.set(attr, media_thumbnail[attr])
```
