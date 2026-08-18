# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2990_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2990_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 16-56 of the vulnerable file.

 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *	\file       htdocs/fourn/index.php
 *	\ingroup    fournisseur
 *	\brief      Home page of suppliers area
 */

require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/fourn/class/fournisseur.commande.class.php';
require_once DOL_DOCUMENT_ROOT.'/fourn/class/fournisseur.facture.class.php';
require_once DOL_DOCUMENT_ROOT.'/categories/class/categorie.class.php';

$langs->load("suppliers");
$langs->load("orders");
$langs->load("companies");

// Security check
$socid = isset($_GET["socid"])?$_GET["socid"]:'';
if ($user->societe_id) $socid=$user->societe_id;
$result = restrictedArea($user, 'societe',$socid,'');


/*
 * View
 */

$commandestatic=new CommandeFournisseur($db);
$facturestatic=new FactureFournisseur($db);
$companystatic=new Societe($db);

llxHeader("",$langs->trans("SuppliersArea"));

print load_fiche_titre($langs->trans("SuppliersArea"));


//print '<table border="0" width="100%" class="notopnoleftnoright">';
//print '<tr><td valign="top" width="30%" class="notopnoleft">';
print '<div class="fichecenter"><div class="fichethirdleft">';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,7 @@
 $langs->load("companies");
 
 // Security check
-$socid = isset($_GET["socid"])?$_GET["socid"]:'';
+$socid = GETPOST("socid", 'int');
 if ($user->societe_id) $socid=$user->societe_id;
 $result = restrictedArea($user, 'societe',$socid,'');
 
@@ -81,7 +81,7 @@
 	while ($i < $num)
 	{
 		$row = $db->fetch_row($resql);
-		
+
 
 		print '<tr class="oddeven">';
 		print '<td>'.$langs->trans($commande->statuts[$row[1]]).'</td>';
@@ -132,7 +132,7 @@
 			$var = true;
 			while ($i < $num)
 			{
-				
+
 				$obj = $db->fetch_object($resql);
 				print '<tr class="oddeven"><td  class="nowrap">';
 				$commandestatic->id=$obj->rowid;
@@ -151,7 +151,7 @@
 			}
 			if ($total>0)
 			{
-				
+
 				print '<tr class="liste_total"><td>'.$langs->trans("Total").'</td><td colspan="2" align="right">'.price($total)."</td></tr>";
 			}
 			print "</table>";
@@ -190,7 +190,7 @@
 			while ($i < $num && $i < 20)
 			{
 				$obj = $db->fetch_object($resql);
-				
+
 				print '<tr class="oddeven"><td class="nowrap">';
 				$facturestatic->ref=$obj->ref;
 				$facturestatic->id=$obj->rowid;
@@ -263,7 +263,7 @@
 
 	while ($obj = $db->fetch_object($resql) )
 	{
-		
+
 
 		print '<tr class="oddeven">';
 		print '<td><a href="card.php?socid='.$obj->socid.'">'.img_object($langs->trans("ShowSupplier"),"company").'</a>';
@@ -300,7 +300,7 @@
 
 	foreach ($companystatic->SupplierCategories as $rowid => $label)
 	{
-		
+
 		print "<tr ".$bc[$var].">\n";
 		print '<td>';
 		$categstatic->id=$rowid;
```
