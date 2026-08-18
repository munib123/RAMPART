# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3545_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3545_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 12-53 of the vulnerable file.

 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *   \file       htdocs/admin/boxes.php
 *   \brief      Page to setup boxes
 *   \version    $Id: boxes.php,v 1.73 2011/08/01 13:26:22 hregis Exp $
 */

require("../main.inc.php");
include_once(DOL_DOCUMENT_ROOT."/includes/boxes/modules_boxes.php");
include_once(DOL_DOCUMENT_ROOT."/lib/admin.lib.php");

$langs->load("admin");

if (!$user->admin)
  accessforbidden();

// Definition des positions possibles pour les boites
$pos_array = array(0);                             // Positions possibles pour une boite (0,1,2,...)
$pos_name = array(0=>$langs->trans("Home"));       // Nom des positions 0=Homepage, 1=...
$boxes = array();

/*
 * Actions
 */
if ((isset($_POST["action"]) && $_POST["action"] == 'addconst'))
{
    dolibarr_set_const($db, "MAIN_BOXES_MAXLINES",$_POST["MAIN_BOXES_MAXLINES"],'',0,'',$conf->entity);
}

if ($_POST["action"] == 'add')
{
	$sql = "SELECT rowid";
	$sql.= " FROM ".MAIN_DB_PREFIX."boxes";
	$sql.= " WHERE fk_user = 0";
	$sql.= " AND box_id = ".$_POST["boxid"];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,8 +29,9 @@
 
 $langs->load("admin");
 
-if (!$user->admin)
-  accessforbidden();
+$id=GETPOST('rowid','int');
+
+if (!$user->admin) accessforbidden();
 
 // Definition des positions possibles pour les boites
 $pos_array = array(0);                             // Positions possibles pour une boite (0,1,2,...)
@@ -101,7 +102,7 @@
 	$db->begin();
 
 	$sql = "DELETE FROM ".MAIN_DB_PREFIX."boxes";
-	$sql.= " WHERE rowid=".$_GET["rowid"];
+	$sql.= " WHERE rowid=".$id;
 	$resql = $db->query($sql);
 
 	// Remove all personalized setup when a box is activated or disabled
@@ -288,7 +289,7 @@
 
 		dol_include_once($sourcefile);
 		$box=new $boxname($db,$obj->note);
-		
+
 		$enabled=true;
 		if ($box->depends && sizeof($box->depends) > 0)
 		{
@@ -297,7 +298,7 @@
 				if (empty($conf->$module->enabled)) $enabled=false;
 			}
 		}
-		
+
 		if ($enabled)
 		{
 			//if (in_array($obj->rowid, $actives) && $box->box_multiple <> 1)
@@ -308,7 +309,7 @@
 			else
 			{
 				$var=!$var;
-	
+
 				if (preg_match('/^([^@]+)@([^@]+)$/i',$box->boximg))
 				{
 					$logo = $box->boximg;
@@ -317,14 +318,14 @@
 				{
 					$logo=preg_replace("/^object_/i","",$box->boximg);
 				}
-	
+
 				print '<form action="'.$_SERVER["PHP_SELF"].'" method="POST">';
 				print '<input type="hidden" name="token" value="'.$_SESSION['newtoken'].'">';
 				print '<tr '.$bc[$var].'>';
 				print '<td>'.img_object("",$logo).' '.$box->boxlabel.'</td>';
 				print '<td>' . ($obj->note?$obj->note:'&nbsp;') . '</td>';
 				print '<td>' . $sourcefile . '</td>';
-	
+
 				// Pour chaque position possible, on affiche un lien
 				// d'activation si boite non deja active pour cette position
 				print '<td>';
@@ -333,11 +334,11 @@
 				print '<input type="hidden" name="boxid" value="'.$obj->rowid.'">';
 				print ' <input type="submit" class="button" name="button" value="'.$langs->trans("Activate").'">';
 				print '</td>';
-	
+
 				print '</tr></form>';
 			}
 		}
-		
+
 		$i++;
 	}
 
```
