# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3544_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3544_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 13-53 of the vulnerable file.

 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 *      \file       htdocs/user/info.php
 *      \ingroup    core
 *		\brief      Page des informations d'un utilisateur
 *		\version    $Id: info.php,v 1.19 2011/07/31 23:19:42 eldy Exp $
*/

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/lib/functions2.lib.php");
require_once(DOL_DOCUMENT_ROOT.'/lib/usergroups.lib.php');
require_once(DOL_DOCUMENT_ROOT."/user/class/user.class.php");

$langs->load("users");

// Security check
$id = isset($_GET["id"])?$_GET["id"]:'';
$fuser = new User($db);
$fuser->fetch($id);

// Security check
$socid=0;
if ($user->societe_id > 0) $socid = $user->societe_id;
$feature2 = (($socid && $user->rights->user->self->creer)?'':'user');
if ($user->id == $_GET["id"])	// A user can always read its own card
{
	$feature2='';
}
$result = restrictedArea($user, 'user', $_GET["id"], '', $feature2);

// If user is not user read and no permission to read other users, we stop
if (($fuser->id != $user->id) && (! $user->rights->user->user->lire))
  accessforbidden();



/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
 $langs->load("users");
 
 // Security check
-$id = isset($_GET["id"])?$_GET["id"]:'';
+$id = GETPOST('id','int');
 $fuser = new User($db);
 $fuser->fetch($id);
 
```
