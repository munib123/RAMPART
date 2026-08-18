# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4066_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4066_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 21-62 of the vulnerable file.

 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */
/**
 * \file		htdocs/accountancy/supplier/card.php
 * \ingroup		Accountancy (Double entries)
 * \brief		Card expense report ventilation
 */
require '../../main.inc.php';

require_once DOL_DOCUMENT_ROOT.'/expensereport/class/expensereport.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formaccounting.class.php';

// Load translation files required by the page
$langs->loadLangs(array("bills", "accountancy", "trips"));

$action = GETPOST('action', 'alpha');
$cancel = GETPOST('cancel', 'alpha');
$backtopage = GETPOST('backtopage', 'alpha');

$codeventil = GETPOST('codeventil');
$id = GETPOST('id');

// Security check
if ($user->socid > 0)
	accessforbidden();


/*
 * Actions
 */

if ($action == 'ventil' && $user->rights->accounting->bind->write)
{
	if (!$cancel)
	{
		if ($codeventil < 0) $codeventil = 0;

		$sql = " UPDATE ".MAIN_DB_PREFIX."expensereport_det";
		$sql .= " SET fk_code_ventilation = ".$codeventil;
		$sql .= " WHERE rowid = ".$id;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,8 +38,8 @@
 $cancel = GETPOST('cancel', 'alpha');
 $backtopage = GETPOST('backtopage', 'alpha');
 
-$codeventil = GETPOST('codeventil');
-$id = GETPOST('id');
+$codeventil = GETPOST('codeventil', 'int');
+$id = GETPOST('id', 'int');
 
 // Security check
 if ($user->socid > 0)
```
