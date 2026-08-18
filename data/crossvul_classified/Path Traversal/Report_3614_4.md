# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3614_4
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3614_4`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 22-65 of the vulnerable file.

/**
 *       \file       htdocs/contact/fiche.php
 *       \ingroup    societe
 *       \brief      Card of a contact
 */

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/comm/action/class/actioncomm.class.php");
require_once(DOL_DOCUMENT_ROOT."/contact/class/contact.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/contact.lib.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/company.lib.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/html.formcompany.class.php");

$langs->load("companies");
$langs->load("users");
$langs->load("other");
$langs->load("commercial");

$mesg=''; $error=0; $errors=array();

$action		= (GETPOST('action') ? GETPOST('action') : 'view');
$confirm	= GETPOST('confirm');
$id			= GETPOST("id");
$socid		= GETPOST("socid");
if ($user->societe_id) $socid=$user->societe_id;

$object = new Contact($db);

// Get object canvas (By default, this is not defined, so standard usage of dolibarr)
$object->getCanvas($id);
$canvas = $object->canvas?$object->canvas:GETPOST("canvas");
if (! empty($canvas))
{
    require_once(DOL_DOCUMENT_ROOT."/core/class/canvas.class.php");
    $objcanvas = new Canvas($db, $action);
    $objcanvas->getCanvas('contact', 'contactcard', $canvas);
}

// Security check
$result = restrictedArea($user, 'contact', $id, 'socpeople&societe', '', '', '', $objcanvas); // If we create a contact with no company (shared contacts), no check on write permission

// Initialize technical object to manage hooks of thirdparties. Note that conf->hooks_modules contains array array
include_once(DOL_DOCUMENT_ROOT.'/core/class/hookmanager.class.php');
$hookmanager=new HookManager($db);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,10 +39,11 @@
 
 $mesg=''; $error=0; $errors=array();
 
-$action		= (GETPOST('action') ? GETPOST('action') : 'view');
-$confirm	= GETPOST('confirm');
-$id			= GETPOST("id");
-$socid		= GETPOST("socid");
+$action		= (GETPOST('action','alpha') ? GETPOST('action','alpha') : 'view');
+$confirm	= GETPOST('confirm','alpha');
+$backtopage = GETPOST('backtopage','alpha');
+$id			= GETPOST('id','int');
+$socid		= GETPOST('socid','int');
 if ($user->societe_id) $socid=$user->societe_id;
 
 $object = new Contact($db);
@@ -76,9 +77,9 @@
 if (empty($reshook))
 {
     // Cancel
-    if (GETPOST("cancel") && GETPOST('backtopage'))
+    if (GETPOST("cancel") && ! empty($backtopage))
     {
-        header("Location: ".GETPOST('backtopage'));
+        header("Location: ".$backtopage);
         exit;
     }
 
@@ -86,7 +87,7 @@
     if ($action == 'confirm_create_user' && $confirm == 'yes' && $user->rights->user->user->creer)
     {
         // Recuperation contact actuel
-        $result = $object->fetch($_GET["id"]);
+        $result = $object->fetch($id);
 
         if ($result > 0)
         {
@@ -172,7 +173,7 @@
         if (! $error && $id > 0)
         {
             $db->commit();
-            if (GETPOST('backtopage')) $url=GETPOST('backtopage');
+            if (! empty($backtopage)) $url=$backtopage;
             else $url='fiche.php?id='.$id;
             Header("Location: ".$url);
             exit;
@@ -368,7 +369,7 @@
             print '<form method="post" name="formsoc" action="'.$_SERVER["PHP_SELF"].'">';
             print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
             print '<input type="hidden" name="action" value="add">';
-            print '<input type="hidden" name="backtopage" value="'.GETPOST('backtopage').'">';
+            print '<input type="hidden" name="backtopage" value="'.$backtopage.'">';
             print '<table class="border" width="100%">';
 
             // Name
@@ -497,7 +498,7 @@
 
             print '<center>';
             print '<input type="submit" class="button" name="add" value="'.$langs->trans("Add").'">';
-            if (GETPOST('backtopage'))
+            if (! empty($backtopage))
             {
                 print ' &nbsp; &nbsp; ';
                 print '<input type="submit" class="button" name="cancel" value="'.$langs->trans("Cancel").'">';
@@ -537,11 +538,11 @@
                 print '</script>';
             }
 
-            print '<form method="post" action="'.$_SERVER["PHP_SELF"].'?id='.GETPOST("id").'" name="formsoc">';
+            print '<form method="post" action="'.$_SERVER["PHP_SELF"].'?id='.$id.'" name="formsoc">';
             print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
-            print '<input type="hidden" name="id" value="'.GETPOST("id").'">';
+            print '<input type="hidden" name="id" value="'.$id.'">';
             print '<input type="hidden" name="action" value="update">';
-            print '<input type="hidden" name="backtopage" value="'.GETPOST('backtopage').'">';
+            print '<input type="hidden" name="backtopage" value="'.$backtopage.'">';
             print '<input type="hidden" name="contactid" value="'.$object->id.'">';
             print '<input type="hidden" name="old_name" value="'.$object->name.'">';
             print '<input type="hidden" name="old_firstname" value="'.$object->firstname.'">';
```
