# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3544_8
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3544_8`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 16-56 of the vulnerable file.

 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *       \file       htdocs/user/param_ihm.php
 *       \brief      Page to show user setup for display
 *       \version    $Id: param_ihm.php,v 1.53 2011/07/31 23:19:43 eldy Exp $
 */

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/lib/functions2.lib.php");
require_once(DOL_DOCUMENT_ROOT."/lib/usergroups.lib.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/html.formadmin.class.php");

$langs->load("companies");
$langs->load("products");
$langs->load("admin");
$langs->load("users");
$langs->load("languages");

// Defini si peux lire/modifier permisssions
$canreaduser=($user->admin || $user->rights->user->user->lire);

if ($_REQUEST["id"])
{
    // $user est le user qui edite, $_REQUEST["id"] est l'id de l'utilisateur edite
    $caneditfield=( (($user->id == $_REQUEST["id"]) && $user->rights->user->self->creer)
    || (($user->id != $_REQUEST["id"]) && $user->rights->user->user->creer));
}

// Security check
$socid=0;
if ($user->societe_id > 0) $socid = $user->societe_id;
$feature2 = (($socid && $user->rights->user->self->creer)?'':'user');
if ($user->id == $_REQUEST["id"])	// A user can always read its own card
{
    $feature2='';
    $canreaduser=1;
}
$result = restrictedArea($user, 'user', $_REQUEST["id"], '', $feature2);
if ($user->id <> $_REQUEST["id"] && ! $canreaduser) accessforbidden();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,30 +33,31 @@
 $langs->load("users");
 $langs->load("languages");
 
+$id=GETPOST('id','int');
+
 // Defini si peux lire/modifier permisssions
 $canreaduser=($user->admin || $user->rights->user->user->lire);
 
-if ($_REQUEST["id"])
-{
-    // $user est le user qui edite, $_REQUEST["id"] est l'id de l'utilisateur edite
-    $caneditfield=( (($user->id == $_REQUEST["id"]) && $user->rights->user->self->creer)
-    || (($user->id != $_REQUEST["id"]) && $user->rights->user->user->creer));
+if ($id)
+{
+    // $user est le user qui edite, $id est l'id de l'utilisateur edite
+    $caneditfield=( (($user->id == $id) && $user->rights->user->self->creer)
+    || (($user->id != $id) && $user->rights->user->user->creer));
 }
 
 // Security check
 $socid=0;
 if ($user->societe_id > 0) $socid = $user->societe_id;
 $feature2 = (($socid && $user->rights->user->self->creer)?'':'user');
-if ($user->id == $_REQUEST["id"])	// A user can always read its own card
+if ($user->id == $id)	// A user can always read its own card
 {
     $feature2='';
     $canreaduser=1;
 }
-$result = restrictedArea($user, 'user', $_REQUEST["id"], '', $feature2);
-if ($user->id <> $_REQUEST["id"] && ! $canreaduser) accessforbidden();
-
-
-$id=! empty($_GET["id"])?$_GET["id"]:$_POST["id"];
+$result = restrictedArea($user, 'user', $id, '', $feature2);
+if ($user->id <> $id && ! $canreaduser) accessforbidden();
+
+
 $dirtop = "../includes/menus/standard";
 $dirleft = "../includes/menus/standard";
 
```
