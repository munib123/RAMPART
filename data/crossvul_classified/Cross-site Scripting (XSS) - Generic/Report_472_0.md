# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 472_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `472_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php
/* Copyright (C) 2016	Laurent Destailleur		<eldy@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *	\file       htdocs/public/notice.php
 *	\brief      Dolibarr page to show a notice.
 *              Default notice is a message to say network connection is off.
 *              You can also call this page with URL: 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 <?php
-/* Copyright (C) 2016	Laurent Destailleur		<eldy@users.sourceforge.net>
+/* Copyright (C) 2016-2018	Laurent Destailleur		<eldy@users.sourceforge.net>
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
@@ -19,13 +19,13 @@
  *	\file       htdocs/public/notice.php
  *	\brief      Dolibarr page to show a notice.
  *              Default notice is a message to say network connection is off.
- *              You can also call this page with URL: 
+ *              You can also call this page with URL:
  *                /public/notice.php?lang=xx_XX&transkey=translation_key  (key must be inside file main.lang, error.lang or other.lang)
  *                /public/notice.php?transphrase=url_encoded_sentence_to_show
  */
 
 define('NOCSRFCHECK',1);
-define('NOLOGIN',1);		
+define('NOLOGIN',1);
 
 require '../main.inc.php';
 
@@ -34,7 +34,7 @@
  * View
  */
 
-if (! GETPOST('transkey') && ! GETPOST('transphrase'))
+if (! GETPOST('transkey','alphanohtml') && ! GETPOST('transphrase','alphanohtml'))
 {
     print 'Sorry, it seems your internet connexion is off.<br>';
     print 'You need to be connected to network to use this software.<br>';
@@ -43,8 +43,8 @@
 {
     $langs->load("error");
     $langs->load("other");
-    
-    if (GETPOST('transphrase')) print GETPOST('transphrase'); 
-    if (GETPOST('transkey')) print $langs->trans(GETPOST('transkey'));
+
+    if (GETPOST('transphrase','alphanohtml')) print GETPOST('transphrase','alphanohtml');
+    if (GETPOST('transkey','alphanohtml')) print $langs->trans(GETPOST('transkey','alphanohtml'));
 }
 
```
