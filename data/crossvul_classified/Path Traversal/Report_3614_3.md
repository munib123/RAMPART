# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in php
**Pair ID:** 3614_3
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3614_3`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *	    \file       htdocs/comm/remx.php
 *      \ingroup    societe
 *		\brief      Page to edit absolute discounts for a customer
 */

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/core/lib/company.lib.php");
require_once(DOL_DOCUMENT_ROOT."/compta/facture/class/facture.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/discount.class.php");

$langs->load("orders");
$langs->load("bills");
$langs->load("companies");

$action=GETPOST('action');

// Security check
$socid = GETPOST("id");
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

if ($action == 'confirm_split' && GETPOST("confirm") == 'yes')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,8 @@
 $langs->load("bills");
 $langs->load("companies");
 
-$action=GETPOST('action');
+$action=GETPOST('action','alpha');
+$backtopage=GETPOST('backtopage','alpha');
 
 // Security check
 $socid = GETPOST("id");
@@ -46,9 +47,9 @@
  * Actions
  */
 
-if (GETPOST('cancel') && GETPOST('backtopage'))
+if (GETPOST('cancel') && ! empty($backtopage))
 {
-     Header("Location: ".GETPOST("backtopage"));
+     Header("Location: ".$backtopage);
      exit;
 }
 
@@ -151,9 +152,9 @@
 
 			if ($discountid > 0)
 			{
-			    if (GETPOST("backtopage"))
+			    if (! empty($backtopage))
 			    {
-			        Header("Location: ".GETPOST("backtopage").'&discountid='.$discountid);
+			        Header("Location: ".$backtopage.'&discountid='.$discountid);
 			        exit;
 			    }
 				else
@@ -228,7 +229,7 @@
 	print '<form method="POST" action="'.$_SERVER["PHP_SELF"].'?id='.$objsoc->id.'">';
 	print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
 	print '<input type="hidden" name="action" value="setremise">';
-    print '<input type="hidden" name="backtopage" value="'.GETPOST('backtopage').'">';
+    print '<input type="hidden" name="backtopage" value="'.$backtopage.'">';
 
 	print '<table class="border" width="100%">';
 
@@ -280,7 +281,7 @@
 
 	print '<center>';
 	print '<input type="submit" class="button" name="submit" value="'.$langs->trans("AddGlobalDiscount").'">';
-    if (GETPOST("backtopage"))
+    if (! empty($backtopage))
     {
         print '&nbsp; &nbsp; ';
 	    print '<input type="submit" class="button" name="cancel" value="'.$langs->trans("Cancel").'">';
```
