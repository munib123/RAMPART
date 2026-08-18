# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3614_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3614_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *	    \file       htdocs/comm/remise.php
 *      \ingroup    societe
 *		\brief      Page to edit relative discount of a customer
 */

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/company.lib.php");
require_once(DOL_DOCUMENT_ROOT."/contact/class/contact.class.php");

$langs->load("companies");
$langs->load("orders");
$langs->load("bills");

$socid = GETPOST("id");
// Security check
if ($user->societe_id > 0)
{
	$socid = $user->societe_id;
}


/*
 * Actions
 */

if (GETPOST('cancel') && GETPOST('backtopage'))
{
     Header("Location: ".GETPOST("backtopage"));
     exit;
}

if (GETPOST("action") == 'setremise')
{
	$soc = New Societe($db);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,21 +30,23 @@
 $langs->load("orders");
 $langs->load("bills");
 
-$socid = GETPOST("id");
+$socid = GETPOST('id','int');
 // Security check
 if ($user->societe_id > 0)
 {
 	$socid = $user->societe_id;
 }
 
+$backtopage = GETPOST('backtopage','alpha');
+
 
 /*
  * Actions
  */
 
-if (GETPOST('cancel') && GETPOST('backtopage'))
-{
-     Header("Location: ".GETPOST("backtopage"));
+if (GETPOST('cancel') && ! empty($backtopage))
+{
+     Header("Location: ".$backtopage);
      exit;
 }
 
@@ -56,9 +58,9 @@
 
 	if ($result > 0)
 	{
-	    if (GETPOST('backtopage'))
+	    if (! empty($backtopage))
 	    {
-    		Header("Location: ".GETPOST('backtopage'));
+    		Header("Location: ".$backtopage);
     		exit;
 	    }
 	    else
@@ -122,7 +124,7 @@
 	print '<form method="POST" action="remise.php?id='.$objsoc->id.'">';
 	print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
 	print '<input type="hidden" name="action" value="setremise">';
-    print '<input type="hidden" name="backtopage" value="'.GETPOST('backtopage').'">';
+    print '<input type="hidden" name="backtopage" value="'.$backtopage.'">';
 
 	print '<table class="border" width="100%">';
 
@@ -138,7 +140,7 @@
 
 	print '<center>';
 	print '<input type="submit" class="button" value="'.$langs->trans("Modify").'">';
-    if (GETPOST("backtopage"))
+    if (! empty($backtopage))
     {
         print '&nbsp; &nbsp; ';
 	    print '<input type="submit" class="button" name="cancel" value="'.$langs->trans("Cancel").'">';
```
