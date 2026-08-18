# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2990_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2990_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *	\file       htdocs/comm/multiprix.php
 *	\ingroup    societe
 *	\brief      Onglet choix du niveau de prix
 */

require '../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/company.lib.php';
require_once DOL_DOCUMENT_ROOT.'/contact/class/contact.class.php';

$langs->load("orders");
$langs->load("companies");

$_socid = $_GET["id"];
// Security check
if ($user->societe_id > 0)
{
	$_socid = $user->societe_id;
}


/*
 * Actions
 */

if ($_POST["action"] == 'setpricelevel')
{
	$soc = New Societe($db);
	$soc->fetch($_GET["id"]);
	$soc->set_price_level($_POST["price_level"],$user);

	header("Location: multiprix.php?id=".$_GET["id"]);
	exit;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,8 @@
 $langs->load("orders");
 $langs->load("companies");
 
-$_socid = $_GET["id"];
+$id = GETPOST('id','int');
+$_socid = GETPOST("id",'int');
 // Security check
 if ($user->societe_id > 0)
 {
@@ -45,10 +46,10 @@
 if ($_POST["action"] == 'setpricelevel')
 {
 	$soc = New Societe($db);
-	$soc->fetch($_GET["id"]);
+	$soc->fetch($id);
 	$soc->set_price_level($_POST["price_level"],$user);
 
-	header("Location: multiprix.php?id=".$_GET["id"]);
+	header("Location: multiprix.php?id=".$id);
 	exit;
 }
 
@@ -87,7 +88,7 @@
 	print '<form method="POST" action="multiprix.php?id='.$objsoc->id.'">';
 	print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
 	print '<input type="hidden" name="action" value="setpricelevel">';
-	
+
 	dol_fiche_head($head, $tabchoice, $langs->trans("ThirdParty"), 0, 'company');
 
 	print '<table width="100%" border="0">';
@@ -122,12 +123,12 @@
 	print "</table>";
 
 	dol_fiche_end();
-	
+
 	print '<div align="center"><input type="submit" class="button" value="'.$langs->trans("Save").'"></div>';
 
 	print "</form>";
 
-	
+
 	print '<br><br>';
 
 
```
