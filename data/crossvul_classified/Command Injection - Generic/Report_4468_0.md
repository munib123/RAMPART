# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in php
**Pair ID:** 4468_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4468_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```php
Lines 17-57 of the vulnerable file.

* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

/**
 *		\file 		htdocs/admin/tools/export_files.php
 *		\brief      Page to export documents into a compressed file
 */

require '../../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/files.lib.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/utils.class.php';
require_once DOL_DOCUMENT_ROOT.'/core/class/html.formfile.class.php';

$langs->load("admin");

$action = GETPOST('action', 'alpha');
$what = GETPOST('what', 'alpha');
$export_type = GETPOST('export_type', 'alpha');
$file = trim(GETPOST('zipfilename_template', 'alpha'));
$compression = GETPOST('compression');

$file = dol_sanitizeFileName($file);
$file = preg_replace('/(\.zip|\.tar|\.tgz|\.gz|\.tar\.gz|\.bz2)$/i', '', $file);

$sortfield = GETPOST('sortfield', 'alpha');
$sortorder = GETPOST('sortorder', 'alpha');
$page = GETPOSTISSET('pageplusone') ? (GETPOST('pageplusone') - 1) : GETPOST("page", 'int');
if (!$sortorder) $sortorder = "DESC";
if (!$sortfield) $sortfield = "date";
if ($page < 0) { $page = 0; }
elseif (empty($page)) $page = 0;
$limit = GETPOST('limit', 'int') ?GETPOST('limit', 'int') : $conf->liste_limit;
$offset = $limit * $page;

if (!$user->admin) accessforbidden();

$errormsg = '';


/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,7 +34,7 @@
 $what = GETPOST('what', 'alpha');
 $export_type = GETPOST('export_type', 'alpha');
 $file = trim(GETPOST('zipfilename_template', 'alpha'));
-$compression = GETPOST('compression');
+$compression = GETPOST('compression', 'aZ09');
 
 $file = dol_sanitizeFileName($file);
 $file = preg_replace('/(\.zip|\.tar|\.tgz|\.gz|\.tar\.gz|\.bz2)$/i', '', $file);
```
