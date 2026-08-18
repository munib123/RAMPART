# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3545_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3545_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 21-62 of the vulnerable file.

 *       \file       htdocs/admin/ihm.php
 *       \brief      Page to setup GUI display options
 *       \version    $Id: ihm.php,v 1.130 2011/07/31 22:23:24 eldy Exp $
 */

require("../main.inc.php");
require_once(DOL_DOCUMENT_ROOT."/lib/usergroups.lib.php");
require_once(DOL_DOCUMENT_ROOT."/lib/admin.lib.php");
require_once(DOL_DOCUMENT_ROOT."/lib/functions2.lib.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/html.formother.class.php");
require_once(DOL_DOCUMENT_ROOT."/core/class/html.formadmin.class.php");

$langs->load("admin");
$langs->load("languages");
$langs->load("other");

$langs->load("companies");
$langs->load("products");
$langs->load("members");

if (!$user->admin)
  accessforbidden();


if (! defined("MAIN_MOTD")) define("MAIN_MOTD","");

// List of supported permanent search area
$searchform=array(	"MAIN_SEARCHFORM_SOCIETE","MAIN_SEARCHFORM_CONTACT",
					"MAIN_SEARCHFORM_PRODUITSERVICE","MAIN_SEARCHFORM_ADHERENT");
$searchformconst=array($conf->global->MAIN_SEARCHFORM_SOCIETE,$conf->global->MAIN_SEARCHFORM_CONTACT,
					$conf->global->MAIN_SEARCHFORM_PRODUITSERVICE,$conf->global->MAIN_SEARCHFORM_ADHERENT);
$searchformtitle=array($langs->trans("Companies"),$langs->trans("Contacts"),
					$langs->trans("ProductsAndServices"),$langs->trans("Members"));
$searchformmodule=array('Module1Name','Module1Name',
					'Module50Name','Module310Name');


if (isset($_POST["action"]) && $_POST["action"] == 'update')
{
	dolibarr_set_const($db, "MAIN_LANG_DEFAULT",       $_POST["main_lang_default"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_MULTILANGS",         $_POST["main_multilangs"],'chaine',0,'',$conf->entity);
	dolibarr_set_const($db, "MAIN_SIZE_LISTE_LIMIT",   $_POST["main_size_liste_limit"],'chaine',0,'',$conf->entity);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,8 +38,7 @@
 $langs->load("products");
 $langs->load("members");
 
-if (!$user->admin)
-  accessforbidden();
+if (!$user->admin) accessforbidden();
 
 
 if (! defined("MAIN_MOTD")) define("MAIN_MOTD","");
```
