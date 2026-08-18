# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 5583_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5583_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-26 of the vulnerable file.

<?php
/*------------------------------------------------------------------------------
     The contents of this file are subject to the Mozilla Public License
     Version 1.1 (the "License"); you may not use this file except in
     compliance with the License. You may obtain a copy of the License at
     http://www.mozilla.org/MPL/

     Software distributed under the License is distributed on an "AS IS"
     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
     License for the specific language governing rights and limitations
     under the License.

     The Original Code is fun_down.php, released on 2003-01-25.

     The Initial Developer of the Original Code is The QuiX project.

     Alternatively, the contents of this file may be used under the terms
     of the GNU General Public License Version 2 or later (the "GPL"), in
     which case the provisions of the GPL are applicable instead of
     those above. If you wish to allow use of your version of this file only
     under the terms of the GPL and not to allow others to use
     your version of this file under the MPL, indicate your decision by
     deleting  the provisions above and replace  them with the notice and
     other provisions required by the GPL.  If you do not delete
     the provisions above, a recipient may use your version of this file
     under either the MPL or the GPL."
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,43 +1,7 @@
 <?php
-/*------------------------------------------------------------------------------
-     The contents of this file are subject to the Mozilla Public License
-     Version 1.1 (the "License"); you may not use this file except in
-     compliance with the License. You may obtain a copy of the License at
-     http://www.mozilla.org/MPL/
 
-     Software distributed under the License is distributed on an "AS IS"
-     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
-     License for the specific language governing rights and limitations
-     under the License.
-
-     The Original Code is fun_down.php, released on 2003-01-25.
-
-     The Initial Developer of the Original Code is The QuiX project.
-
-     Alternatively, the contents of this file may be used under the terms
-     of the GNU General Public License Version 2 or later (the "GPL"), in
-     which case the provisions of the GPL are applicable instead of
-     those above. If you wish to allow use of your version of this file only
-     under the terms of the GPL and not to allow others to use
-     your version of this file under the MPL, indicate your decision by
-     deleting  the provisions above and replace  them with the notice and
-     other provisions required by the GPL.  If you do not delete
-     the provisions above, a recipient may use your version of this file
-     under either the MPL or the GPL."
-------------------------------------------------------------------------------*/
-/*------------------------------------------------------------------------------
-Author: The QuiX project
-	quix@free.fr
-	http://www.quix.tk
-	http://quixplorer.sourceforge.net
-
-Comment:
-	QuiXplorer Version 2.3
-	File-Download Functions
-
-	Have Fun...
-------------------------------------------------------------------------------*/
-require_once("./_include/permissions.php");
+require_once("_include/fun_archive.php");
+require_once("_include/permissions.php");
 require_once("qxpage.php");
 
 /**
@@ -46,52 +10,42 @@
  **/
 function download_selected($dir)
 {
-    $dir = get_abs_dir($dir);
-    global $site_name;
     require_once("_include/fun_archive.php");
     $items = qxpage_selected_items();
-
-    // check if user selected any items to download
-    switch (count($items))
-    {
-        case 0:
-            show_error($GLOBALS["error_msg"]["miscselitems"]);
-        case 1:
-            if (is_file($items[0]))
-            {
-                download_item( $dir, $items[0] );
-                break;
-            }
-            // nobreak, downloading a directory is done
-            // with the zip file
-        default:
-            zip_download( $dir, $items );
-    }
+    _download_items($dir, $items);
 }
 
 // download file
 function download_item($dir, $item)
 {
-	// Security Fix:
-	$item=basename($item);
-
-	if (!permissions_grant($dir, $item, "read"))
-		show_error($GLOBALS["error_msg"]["accessfunc"]);
-
-	if (!get_is_file($dir,$item))
-    {
-        _debug("error download");
-        show_error($item.": ".$GLOBALS["error_msg"]["fileexist"]);
-    }
-	if (!get_show_item($dir, $item))
-        show_error($item.": ".$GLOBALS["error_msg"]["accessfile"]);
-
-	$abs_item = get_abs_item($dir,$item);
-    _download($abs_item, $item);
+    _download_items($dir, array($item));
 }
 
-function _download_header($filename, $filesize = 0)
+function _download_items($dir, $items)
 {
+    // check if user selected any items to download
+    _debug("count items: '$items[0]'");
+    if (count($items) == 0)
+        show_error($GLOBALS["error_msg"]["miscselitems"]);
+
+    // check if user has permissions to download
+    // this file
+    if ( ! _is_download_allowed($dir, $items) )
+		show_error( $GLOBALS["error_msg"]["accessitem"] );
+
+    // if we have exactly one file and this is a real
+    // file we directly download it
+    if ( count($items) == 1 && get_is_file( $dir, $items[0] ) )
+    {
+        $abs_item = get_abs_item($dir, $items[0]);
+        _download($abs_item, $items[0]);
+    }
+
+    // otherwise we do the zip download
+    zip_download( get_abs_dir($dir), $items );
+}
+
+function _download_header($filename, $filesize = 0) {
 	$browser=id_browser();
 	header('Content-Type: '.(($browser=='IE' || $browser=='OPERA')?
 		'application/octetstream':'application/octet-stream'));
@@ -118,4 +72,17 @@
 	exit;
 }
 
+function _is_download_allowed( $dir, $items )
+{
+    foreach ($items as $file)
+    {
+        if (!permissions_grant($dir, $file, "read"))
+            return false;
+
+        if (!get_show_item($dir, $file))
+            return false;
+    }
+
+    return true;
+}
 ?>
```
