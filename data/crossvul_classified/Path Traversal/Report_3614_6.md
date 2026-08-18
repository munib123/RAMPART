# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3614_6
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3614_6`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
/* Copyright (C) 2004-2007 Rodolphe Quiedeville <rodolphe@quiedeville.org>
 * Copyright (C) 2004-2012 Laurent Destailleur  <eldy@users.sourceforge.net>
 * Copyright (C) 2005      Simon Tosser         <simon@kornog-computing.com>
 * Copyright (C) 2005-2011 Regis Houssin        <regis@dolibarr.fr>
 * Copyright (C) 2010	   Pierre Morin         <pierre.morin@auguria.net>
 * Copyright (C) 2010	   Juanjo Menent        <jmenent@2byte.es>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * or see http://www.gnu.org/
 */

/**
 *	\file       htdocs/document.php
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 /* Copyright (C) 2004-2007 Rodolphe Quiedeville <rodolphe@quiedeville.org>
  * Copyright (C) 2004-2012 Laurent Destailleur  <eldy@users.sourceforge.net>
  * Copyright (C) 2005      Simon Tosser         <simon@kornog-computing.com>
- * Copyright (C) 2005-2011 Regis Houssin        <regis@dolibarr.fr>
+ * Copyright (C) 2005-2012 Regis Houssin        <regis@dolibarr.fr>
  * Copyright (C) 2010	   Pierre Morin         <pierre.morin@auguria.net>
  * Copyright (C) 2010	   Juanjo Menent        <jmenent@2byte.es>
  *
@@ -50,10 +50,10 @@
 require_once(DOL_DOCUMENT_ROOT.'/core/lib/files.lib.php');
 
 $encoding = '';
-$action = GETPOST("action");
-$original_file = GETPOST("file");	// Do not use urldecode here ($_GET are already decoded by PHP).
-$modulepart = GETPOST("modulepart");
-$urlsource = GETPOST("urlsource");
+$action = GETPOST('action','alpha');
+$original_file = GETPOST('file','alpha');	// Do not use urldecode here ($_GET are already decoded by PHP).
+$modulepart = GETPOST('modulepart','alpha');
+$urlsource = GETPOST('urlsource','alpha');
 
 // Security check
 if (empty($modulepart)) accessforbidden('Bad value for parameter modulepart');
@@ -72,7 +72,7 @@
 
 // Define mime type
 $type = 'application/octet-stream';
-if (GETPOST('type')) $type=GETPOST('type');
+if (GETPOST('type','alpha')) $type=GETPOST('type','alpha');
 else $type=dol_mimetype($original_file);
 //print 'X'.$type.'-'.$original_file;exit;
 
```
