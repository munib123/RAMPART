# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 4796_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4796_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 14-48 of the vulnerable file.

// | WITHOUT ANY WARRANTY; without even the implied warranty of            |
// | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU      |
// | General Public License for more details.                              |
// |                                                                       |
// | You should have received a copy of the GNU General Public License     |
// | along with this program; if not, write to the Free Software           |
// | Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, |
// | USA.                                                                  |
// +-----------------------------------------------------------------------+

if( !defined("PHPWG_ROOT_PATH") )
{
  die ("Hacking attempt!");
}

include_once(PHPWG_ROOT_PATH.'admin/include/tabsheet.class.php');

$my_base_url = get_root_url().'admin.php?page=languages';

if (isset($_GET['tab']))
  $page['tab'] = $_GET['tab'];
else
  $page['tab'] = 'installed';

$tabsheet = new tabsheet();
$tabsheet->set_id('languages');
$tabsheet->select($page['tab']);
$tabsheet->assign();

if ($page['tab'] == 'update')
  include(PHPWG_ROOT_PATH.'admin/updates_ext.php');
else
  include(PHPWG_ROOT_PATH.'admin/languages_'.$page['tab'].'.php');

?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,9 +31,14 @@
 $my_base_url = get_root_url().'admin.php?page=languages';
 
 if (isset($_GET['tab']))
+{
+  check_input_parameter('tab', $_GET, false, '/^(installed|update|new)$/');
   $page['tab'] = $_GET['tab'];
+}
 else
+{
   $page['tab'] = 'installed';
+}
 
 $tabsheet = new tabsheet();
 $tabsheet->set_id('languages');
```
