# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3614_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3614_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 1-25 of the vulnerable file.

<?php
/* Copyright (C) 2001-2005 Rodolphe Quiedeville <rodolphe@quiedeville.org>
 * Copyright (C) 2004-2012 Laurent Destailleur  <eldy@users.sourceforge.net>
 * Copyright (C) 2005      Simon TOSSER         <simon@kornog-computing.com>
 * Copyright (C) 2005-2011 Regis Houssin        <regis@dolibarr.fr>
 * Copyright (C) 2010      Juanjo Menent        <jmenent@2byte.es>
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
 */

/**
 *       \file       htdocs/comm/action/fiche.php
 *       \ingroup    agenda
 *       \brief      Page for event card
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 /* Copyright (C) 2001-2005 Rodolphe Quiedeville <rodolphe@quiedeville.org>
  * Copyright (C) 2004-2012 Laurent Destailleur  <eldy@users.sourceforge.net>
  * Copyright (C) 2005      Simon TOSSER         <simon@kornog-computing.com>
- * Copyright (C) 2005-2011 Regis Houssin        <regis@dolibarr.fr>
+ * Copyright (C) 2005-2012 Regis Houssin        <regis@dolibarr.fr>
  * Copyright (C) 2010      Juanjo Menent        <jmenent@2byte.es>
  *
  * This program is free software; you can redistribute it and/or modify
@@ -43,11 +43,12 @@
 $langs->load("orders");
 $langs->load("agenda");
 
-$action=GETPOST("action");
+$action=GETPOST('action','alpha');
+$backtopage=GETPOST('backtopage','alpha');
 
 // Security check
-$socid = GETPOST('socid');
-$id = GETPOST('id');
+$socid = GETPOST('socid','int');
+$id = GETPOST('id','int');
 if ($user->societe_id) $socid=$user->societe_id;
 //$result = restrictedArea($user, 'agenda', $id, 'actioncomm', 'actions', '', 'id');
 
@@ -66,9 +67,7 @@
 {
 	$error=0;
 
-    $backtopage='';
-    if (! empty($_POST["backtopage"])) $backtopage=$_POST["backtopage"];
-    if (! $backtopage)
+    if (empty($backtopage))
     {
         if ($socid > 0) $backtopage = DOL_URL_ROOT.'/societe/agenda.php?socid='.$socid;
         else $backtopage=DOL_URL_ROOT.'/comm/action/index.php';
@@ -339,14 +338,9 @@
 	}
 	else
 	{
-		if (! empty($_POST["from"]))  // deprecated. Use backtopage instead
-		{
-			header("Location: ".$_POST["from"]);
-			exit;
-		}
-        if (! empty($_POST["backtopage"]))
+        if (! empty($backtopage))
         {
-            header("Location: ".$_POST["backtopage"]);
+            header("Location: ".$backtopage);
             exit;
         }
 	}
@@ -426,7 +420,7 @@
 	print '<form name="formaction" action="'.DOL_URL_ROOT.'/comm/action/fiche.php" method="POST">';
 	print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
 	print '<input type="hidden" name="action" value="add_action">';
-	if (GETPOST("backtopage")) print '<input type="hidden" name="backtopage" value="'.(GETPOST("backtopage") != 1 ? GETPOST("backtopage") : $_SERVER["HTTP_REFERER"]).'">';
+	print '<input type="hidden" name="backtopage" value="'.(! empty($backtopage) ? $backtopage : $_SERVER["HTTP_REFERER"]).'">';
 
 	if (GETPOST("actioncode") == 'AC_RDV') print_fiche_titre($langs->trans("AddActionRendezVous"));
 	else print_fiche_titre($langs->trans("AddAnAction"));
@@ -679,7 +673,7 @@
 		print '<input type="hidden" name="action" value="update">';
 		print '<input type="hidden" name="id" value="'.$id.'">';
 		print '<input type="hidden" name="ref_ext" value="'.$act->ref_ext.'">';
-		if (GETPOST("backtopage")) print '<input type="hidden" name="backtopage" value="'.(GETPOST("backtopage") ? GETPOST("backtopage") : $_SERVER["HTTP_REFERER"]).'">';
+		print '<input type="hidden" name="backtopage" value="'.(! empty($backtopage) ? $backtopage : $_SERVER["HTTP_REFERER"]).'">';
 
 		print '<table class="border" width="100%">';
 
```
