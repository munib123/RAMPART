# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3613_5
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3613_5`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 17-58 of the vulnerable file.

 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *	\file       htdocs/projet/fiche.php
 *	\ingroup    projet
 *	\brief      Project card
 */

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/projet/class/project.class.php");
require_once(DOL_DOCUMENT_ROOT."/projet/class/task.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/project.lib.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/html.formfile.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/modules/project/modules_project.php");

$langs->load("projects");
$langs->load('companies');

$id=GETPOST('id','int');
$ref = GETPOST('ref');
$action=GETPOST('action');

if ($id == '' && $ref == '' && ($action != "create" && $action != "add" && $action != "update" && ! $_POST["cancel"])) accessforbidden();

$mine = GETPOST('mode')=='mine' ? 1 : 0;
//if (! $user->rights->projet->all->lire) $mine=1;	// Special for projects

// Security check
$socid=0;
if ($user->societe_id > 0) $socid=$user->societe_id;
$result = restrictedArea($user, 'projet', $id);




/*
 * Actions
 */

// Cancel
if (GETPOST("cancel") && GETPOST('backtopage'))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,8 +34,9 @@
 $langs->load('companies');
 
 $id=GETPOST('id','int');
-$ref = GETPOST('ref');
-$action=GETPOST('action');
+$ref = GETPOST('ref','alpha');
+$action=GETPOST('action','alpha');
+$backtopage=GETPOST('backtopage','alpha');
 
 if ($id == '' && $ref == '' && ($action != "create" && $action != "add" && $action != "update" && ! $_POST["cancel"])) accessforbidden();
 
@@ -55,9 +56,9 @@
  */
 
 // Cancel
-if (GETPOST("cancel") && GETPOST('backtopage'))
-{
-    header("Location: ".GETPOST('backtopage'));
+if (GETPOST("cancel") && ! empty($backtopage))
+{
+    header("Location: ".$backtopage);
     exit;
 }
 
@@ -276,7 +277,7 @@
     print '<form action="'.$_SERVER["PHP_SELF"].'" method="POST">';
     print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
     print '<input type="hidden" name="action" value="add">';
-    print '<input type="hidden" name="backtopage" value="'.GETPOST('backtopage').'">';
+    print '<input type="hidden" name="backtopage" value="'.$backtopage.'">';
 
     print '<table class="border" width="100%">';
 
@@ -332,7 +333,7 @@
 
     print '<br><center>';
     print '<input type="submit" class="button" value="'.$langs->trans("Create").'">';
-    if (GETPOST('backtopage'))
+    if (! empty($backtopage))
     {
         print ' &nbsp; &nbsp; ';
 	    print '<input type="submit" class="button" name="cancel" value="'.$langs->trans("Cancel").'">';
```
