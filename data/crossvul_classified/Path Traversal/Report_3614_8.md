# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3614_8
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3614_8`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 19-59 of the vulnerable file.


/**
 *	\file       htdocs/projet/tasks.php
 *	\ingroup    projet
 *	\brief      List all tasks of a project
 */

require ("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/projet/class/project.class.php");
require_once(DOL_DOCUMENT_ROOT."/projet/class/task.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/project.lib.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/date.lib.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/html.formother.class.php");

$langs->load("users");
$langs->load("projects");

$action = GETPOST('action', 'alpha');
$id = GETPOST('id', 'int');
$ref = GETPOST('ref', 'alpha');

$mode = GETPOST('mode', 'alpha');
$mine = ($mode == 'mine' ? 1 : 0);
//if (! $user->rights->projet->all->lire) $mine=1;	// Special for projects

// Security check
$socid=0;
if ($user->societe_id > 0) $socid = $user->societe_id;
//$result = restrictedArea($user, 'projet', $projectid);
if (!$user->rights->projet->lire) accessforbidden();

$progress=GETPOST('progress', 'int');
$label=GETPOST('label', 'alpha');
$description=GETPOST('description', 'alpha');

$userAccess=0;

$object = new Project($db);


/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,7 @@
 $action = GETPOST('action', 'alpha');
 $id = GETPOST('id', 'int');
 $ref = GETPOST('ref', 'alpha');
+$backtopage=GETPOST('backtopage','alpha');
 
 $mode = GETPOST('mode', 'alpha');
 $mine = ($mode == 'mine' ? 1 : 0);
@@ -111,9 +112,9 @@
 
 		if (! $error)
 		{
-		    if (GETPOST('backtopage'))
+		    if (! empty($backtopage))
 			{
-				Header("Location: ".GETPOST('backtopage'));
+				Header("Location: ".$backtopage);
 				exit;
 			}
 			else if (empty($projectid))
@@ -125,9 +126,9 @@
 	}
 	else
 	{
-		if (GETPOST('backtopage'))
-		{
-			Header("Location: ".GETPOST('backtopage'));
+		if (! empty($backtopage))
+		{
+			Header("Location: ".$backtopage);
 			exit;
 		}
 	    else if (empty($id))
@@ -219,7 +220,7 @@
 	print '<form action="'.$_SERVER['PHP_SELF'].'" method="POST">';
 	print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
 	print '<input type="hidden" name="action" value="createtask">';
-	print '<input type="hidden" name="backtopage" value="'.GETPOST('backtopage').'">';
+	print '<input type="hidden" name="backtopage" value="'.$backtopage.'">';
 	if (! empty($object->id)) print '<input type="hidden" name="id" value="'.$object->id.'">';
 	if (! empty($mode)) print '<input type="hidden" name="mode" value="'.$mode.'">';
 
```
