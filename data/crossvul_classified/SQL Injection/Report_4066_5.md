# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 4066_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4066_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 11-51 of the vulnerable file.

 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

if (! defined('NOTOKENRENEWAL')) define('NOTOKENRENEWAL', '1');
if (! defined('NOREQUIREMENU'))  define('NOREQUIREMENU', '1');
if (! defined('NOREQUIREHTML'))  define('NOREQUIREHTML', '1');
if (! defined('NOREQUIREAJAX'))  define('NOREQUIREAJAX', '1');
if (! defined('NOREQUIRESOC'))   define('NOREQUIRESOC', '1');

require '../../main.inc.php';
require_once DOL_DOCUMENT_ROOT.'/product/class/product.class.php';
require_once DOL_DOCUMENT_ROOT.'/variants/class/ProductAttribute.class.php';
require_once DOL_DOCUMENT_ROOT.'/variants/class/ProductAttributeValue.class.php';

header('Content-Type: application/json');

$id = GETPOST('id');

if (!$id) {
    print json_encode(array(
        'error' => 'ID not set'
    ));
    exit();
}

$prodattr = new ProductAttribute($db);

if ($prodattr->fetch($id) < 0) {
    print json_encode(array(
        'error' => 'Attribute not found'
    ));
    exit();
}

$prodattrval = new ProductAttributeValue($db);

$res = $prodattrval->fetchAllByProductAttribute($id);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,7 @@
 
 header('Content-Type: application/json');
 
-$id = GETPOST('id');
+$id = GETPOST('id', 'int');
 
 if (!$id) {
     print json_encode(array(
```
