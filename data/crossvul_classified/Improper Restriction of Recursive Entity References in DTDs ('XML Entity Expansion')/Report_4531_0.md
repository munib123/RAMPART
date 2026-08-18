# CrossVul Fix Pair: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') in python
**Pair ID:** 4531_0
**Vulnerability Class:** Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
**CWE:** CWE-776
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4531_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') - If the DTD contains a large number of nested or recursive entities, this can lead to explosive growth of data when parsed, causing a denial of service.

## Vulnerable Code
```python
Lines 1-26 of the vulnerable file.

# -*- coding: utf-8 -*-
'''
    feedgen.entry
    ~~~~~~~~~~~~~

    :copyright: 2013, Lars Kiesow <lkiesow@uos.de>

    :license: FreeBSD and LGPL, see license.* for more details.
'''

from datetime import datetime

import dateutil.parser
import dateutil.tz
import warnings
from lxml import etree

from feedgen.compat import string_types
from feedgen.util import ensure_format, formatRFC2822


def _add_text_elm(entry, data, name):
    """Add a text subelement to an entry"""
    if not data:
        return

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,7 +3,7 @@
     feedgen.entry
     ~~~~~~~~~~~~~
 
-    :copyright: 2013, Lars Kiesow <lkiesow@uos.de>
+    :copyright: 2013-2020, Lars Kiesow <lkiesow@uos.de>
 
     :license: FreeBSD and LGPL, see license.* for more details.
 '''
@@ -13,10 +13,11 @@
 import dateutil.parser
 import dateutil.tz
 import warnings
-from lxml import etree
+
+from lxml.etree import CDATA  # nosec - adding CDATA entry is safe
 
 from feedgen.compat import string_types
-from feedgen.util import ensure_format, formatRFC2822
+from feedgen.util import ensure_format, formatRFC2822, xml_fromstring, xml_elem
 
 
 def _add_text_elm(entry, data, name):
@@ -24,7 +25,7 @@
     if not data:
         return
 
-    elm = etree.SubElement(entry, name)
+    elm = xml_elem(name, entry)
     type_ = data.get('type')
     if data.get('src'):
         if name != 'content':
@@ -34,16 +35,14 @@
     elif data.get(name):
         # Surround xhtml with a div tag, parse it and embed it
         if type_ == 'xhtml':
-            elm.append(etree.fromstring(
-                '<div xmlns="http://www.w3.org/1999/xhtml">' +
-                data.get(name) + '</div>'))
+            xhtml = '<div xmlns="http://www.w3.org/1999/xhtml">' \
+                    + data.get(name) + '</div>'
+            elm.append(xml_fromstring(xhtml))
         elif type_ == 'CDATA':
-            elm.text = etree.CDATA(
-                    data.get(name))
+            elm.text = CDATA(data.get(name))
         # Parse XML and embed it
         elif type_ and (type_.endswith('/xml') or type_.endswith('+xml')):
-            elm.append(etree.fromstring(
-                data[name]))
+            elm.append(xml_fromstring(data[name]))
         # Embed the text in escaped form
         elif not type_ or type_.startswith('text') or type_ == 'html':
             elm.text = data.get(name)
@@ -102,14 +101,14 @@
 
     def atom_entry(self, extensions=True):
         '''Create an ATOM entry and return it.'''
-        entry = etree.Element('entry')
+        entry = xml_elem('entry')
         if not (self.__atom_id and self.__atom_title and self.__atom_updated):
             raise ValueError('Required fields not set')
-        id = etree.SubElement(entry, 'id')
+        id = xml_elem('id', entry)
         id.text = self.__atom_id
-        title = etree.SubElement(entry, 'title')
+        title = xml_elem('title', entry)
         title.text = self.__atom_title
-        updated = etree.SubElement(entry, 'updated')
+        updated = xml_elem('updated', entry)
         updated.text = self.__atom_updated.isoformat()
 
         # An entry must contain an alternate link if there is no content
@@ -125,20 +124,20 @@
             # Atom requires a name. Skip elements without.
             if not a.get('name'):
                 continue
-            author = etree.SubElement(entry, 'author')
-            name = etree.SubElement(author, 'name')
+            author = xml_elem('author', entry)
+            name = xml_elem('name', author)
             name.text = a.get('name')
             if a.get('email'):
-                email = etree.SubElement(author, 'email')
+                email = xml_elem('email', author)
                 email.text = a.get('email')
             if a.get('uri'):
-                uri = etree.SubElement(author, 'uri')
+                uri = xml_elem('uri', author)
                 uri.text = a.get('uri')
 
         _add_text_elm(entry, self.__atom_content, 'content')
 
         for l in self.__atom_link or []:
-            link = etree.SubElement(entry, 'link', href=l['href'])
+            link = xml_elem('link', entry, href=l['href'])
             if l.get('rel'):
                 link.attrib['rel'] = l['rel']
             if l.get('type'):
@@ -153,7 +152,7 @@
         _add_text_elm(entry, self.__atom_summary, 'summary')
 
         for c in self.__atom_category or []:
-            cat = etree.SubElement(entry, 'category', term=c['term'])
+            cat = xml_elem('category', entry, term=c['term'])
             if c.get('scheme'):
                 cat.attrib['scheme'] = c['scheme']
             if c.get('label'):
@@ -164,32 +163,31 @@
             # Atom requires a name. Skip elements without.
             if not c.get('name'):
                 continue
-            contrib = etree.SubElement(entry, 'contributor')
-            name = etree.SubElement(contrib, 'name')
+            contrib = xml_elem('contributor', entry)
+            name = xml_elem('name', contrib)
             name.text = c.get('name')
             if c.get('email'):
-                email = etree.SubElement(contrib, 'email')
+                email = xml_elem('email', contrib)
                 email.text = c.get('email')
             if c.get('uri'):
-                uri = etree.SubElement(contrib, 'uri')
+                uri = xml_elem('uri', contrib)
                 uri.text = c.get('uri')
 
         if self.__atom_published:
-            published = etree.SubElement(entry, 'published')
+            published = xml_elem('published', entry)
             published.text = self.__atom_published.isoformat()
 
         if self.__atom_rights:
-            rights = etree.SubElement(entry, 'rights')
+            rights = xml_elem('rights', entry)
             rights.text = self.__atom_rights
 
         if self.__atom_source:
-            source = etree.SubElement(entry, 'source')
+            source = xml_elem('source', entry)
             if self.__atom_source.get('title'):
-                source_title = etree.SubElement(source, 'title')
+                source_title = xml_elem('title', source)
                 source_title.text = self.__atom_source['title']
             if self.__atom_source.get('link'):
-                etree.SubElement(source, 'link',
-                                 href=self.__atom_source['link'])
+                xml_elem('link', source, href=self.__atom_source['link'])
 
         if extensions:
             for ext in self.__extensions.values() or []:
@@ -200,60 +198,59 @@
 
     def rss_entry(self, extensions=True):
         '''Create a RSS item and return it.'''
-        entry = etree.Element('item')
+        entry = xml_elem('item')
         if not (self.__rss_title or
                 self.__rss_description or
                 self.__rss_content):
             raise ValueError('Required fields not set')
         if self.__rss_title:
-            title = etree.SubElement(entry, 'title')
+            title = xml_elem('title', entry)
             title.text = self.__rss_title
         if self.__rss_link:
-            link = etree.SubElement(entry, 'link')
+            link = xml_elem('link', entry)
             link.text = self.__rss_link
         if self.__rss_description and self.__rss_content:
-            description = etree.SubElement(entry, 'description')
+            description = xml_elem('description', entry)
             description.text = self.__rss_description
             XMLNS_CONTENT = 'http://purl.org/rss/1.0/modules/content/'
-            content = etree.SubElement(entry, '{%s}encoded' % XMLNS_CONTENT)
-            content.text = etree.CDATA(self.__rss_content['content']) \
+            content = xml_elem('{%s}encoded' % XMLNS_CONTENT, entry)
+            content.text = CDATA(self.__rss_content['content']) \
                 if self.__rss_content.get('type', '') == 'CDATA' \
                 else self.__rss_content['content']
         elif self.__rss_description:
-            description = etree.SubElement(entry, 'description')
+            description = xml_elem('description', entry)
             description.text = self.__rss_description
         elif self.__rss_content:
-            description = etree.SubElement(entry, 'description')
-            description.text = etree.CDATA(self.__rss_content['content']) \
+            description = xml_elem('description', entry)
+            description.text = CDATA(self.__rss_content['content']) \
... (diff truncated)
```
