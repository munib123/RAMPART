# CrossVul Fix Pair: Deserialization of Untrusted Data in python
**Pair ID:** 654_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `654_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```python
Lines 1-29 of the vulnerable file.

#!/usr/bin/env python2
# vim:fileencoding=utf-8
from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

__license__ = 'GPL v3'
__copyright__ = '2013, Kovid Goyal <kovid at kovidgoyal.net>'

import cPickle

from PyQt5.Qt import (
    Qt, QListWidget, QListWidgetItem, QItemSelectionModel, QAction,
    QGridLayout, QPushButton, QIcon, QWidget, pyqtSignal, QLabel)

from calibre.gui2 import choose_save_file, choose_files
from calibre.utils.icu import sort_key


class BookmarksList(QListWidget):

    changed = pyqtSignal()
    bookmark_activated = pyqtSignal(object)

    def __init__(self, parent=None):
        QListWidget.__init__(self, parent)
        self.setDragEnabled(True)
        self.setDragDropMode(self.InternalMove)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setAlternatingRowColors(True)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 __license__ = 'GPL v3'
 __copyright__ = '2013, Kovid Goyal <kovid at kovidgoyal.net>'
 
-import cPickle
+import json
 
 from PyQt5.Qt import (
     Qt, QListWidget, QListWidgetItem, QItemSelectionModel, QAction,
@@ -186,10 +186,10 @@
         self.edited.emit(bm)
 
     def bm_to_item(self, bm):
-        return bytearray(cPickle.dumps(bm, -1))
+        return bm.copy()
 
     def item_to_bm(self, item):
-        return cPickle.loads(bytes(item.data(Qt.UserRole)))
+        return item.data(Qt.UserRole).copy()
 
     def get_bookmarks(self):
         return list(self)
@@ -197,21 +197,21 @@
     def export_bookmarks(self):
         filename = choose_save_file(
             self, 'export-viewer-bookmarks', _('Export bookmarks'),
-            filters=[(_('Saved bookmarks'), ['pickle'])], all_files=False, initial_filename='bookmarks.pickle')
+            filters=[(_('Saved bookmarks'), ['calibre-bookmarks'])], all_files=False, initial_filename='bookmarks.calibre-bookmarks')
         if filename:
-            with open(filename, 'wb') as fileobj:
-                cPickle.dump(self.get_bookmarks(), fileobj, -1)
+            with lopen(filename, 'wb') as fileobj:
+                fileobj.write(json.dumps(self.get_bookmarks(), indent=True))
 
     def import_bookmarks(self):
         files = choose_files(self, 'export-viewer-bookmarks', _('Import bookmarks'),
-            filters=[(_('Saved bookmarks'), ['pickle'])], all_files=False, select_only_single_file=True)
+            filters=[(_('Saved bookmarks'), ['calibre-bookmarks'])], all_files=False, select_only_single_file=True)
         if not files:
             return
         filename = files[0]
 
         imported = None
-        with open(filename, 'rb') as fileobj:
-            imported = cPickle.load(fileobj)
+        with lopen(filename, 'rb') as fileobj:
+            imported = json.load(fileobj)
 
         if imported is not None:
             bad = False
```
