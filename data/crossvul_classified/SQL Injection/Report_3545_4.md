# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3545_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3545_4`)

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
 *      \file       htdocs/user/group/index.php
 * 		\ingroup	core
 *      \brief      Page of user groups
 *      \version    $Id: index.php,v 1.24 2011/07/31 23:21:25 eldy Exp $
 */

require("../../main.inc.php");

if (! empty($conf->global->MAIN_USE_ADVANCED_PERMS))
{
	if (! $user->rights->user->group_advance->read && ! $user->admin) accessforbidden();
}

$langs->load("users");

$sall=isset($_GET["sall"])?$_GET["sall"]:$_POST["sall"];

$sortfield = GETPOST("sortfield",'alpha');
$sortorder = GETPOST("sortorder",'alpha');
$page = GETPOST("page",'int');
if ($page == -1) { $page = 0; }
$offset = $conf->liste_limit * $page;
$pageprev = $page - 1;
$pagenext = $page + 1;

if (! $sortfield) $sortfield="g.nom";
if (! $sortorder) $sortorder="ASC";


/*
 * View
 */

llxHeader();

print_fiche_titre($langs->trans("ListOfGroups"));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,7 +33,7 @@
 
 $langs->load("users");
 
-$sall=isset($_GET["sall"])?$_GET["sall"]:$_POST["sall"];
+$sall=GETPOST("sall");
 
 $sortfield = GETPOST("sortfield",'alpha');
 $sortorder = GETPOST("sortorder",'alpha');
@@ -61,9 +61,9 @@
 $sql.= " WHERE g.entity IN (0,".$conf->entity.")";
 if ($_POST["search_group"])
 {
-    $sql .= " AND (g.nom like '%".$_POST["search_group"]."%' OR g.note like '%".$_POST["search_group"]."%')";
+    $sql .= " AND (g.nom like '%".$db->escape($_POST["search_group"])."%' OR g.note like '%".$db->escape($_POST["search_group"])."%')";
 }
-if ($sall) $sql.= " AND (g.nom like '%".$sall."%' OR g.note like '%".$sall."%')";
+if ($sall) $sql.= " AND (g.nom like '%".$db->escape($sall)."%' OR g.note like '%".$db->escape($sall)."%')";
 $sql.= " GROUP BY g.rowid, g.nom, g.entity, g.datec";
 $sql.= $db->order($sortfield,$sortorder);
 
@@ -73,7 +73,7 @@
     $num = $db->num_rows($resql);
     $i = 0;
 
-    $param="search_group=$search_group&amp;sall=$sall";
+    $param="search_group=".$search_group."&amp;sall=".$sall;
     print "<table class=\"noborder\" width=\"100%\">";
     print '<tr class="liste_titre">';
     print_liste_field_titre($langs->trans("Group"),$_SERVER["PHP_SELF"],"g.nom",$param,"","",$sortfield,$sortorder);
```
