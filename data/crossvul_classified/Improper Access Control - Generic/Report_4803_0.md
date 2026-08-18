# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 4803_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4803_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 15-55 of the vulnerable file.

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

include_once(PHPWG_ROOT_PATH.'admin/include/functions.php');
check_status(ACCESS_ADMINISTRATOR);

$sections = explode('/', $_GET['section'] );
for ($i=0; $i<count($sections); $i++)
{
  if (empty($sections[$i]) or $sections[$i]=='..')
  {
    unset($sections[$i]);
    $i--;
  }
}

if (count($sections)<2)
{
  die('Invalid plugin URL');
}

$plugin_id = $sections[0];

if (!preg_match('/^[\w-]+$/', $plugin_id))
{
  die('Invalid plugin identifier');
}

if ( !isset($pwg_loaded_plugins[$plugin_id]) )
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,10 +32,16 @@
 $sections = explode('/', $_GET['section'] );
 for ($i=0; $i<count($sections); $i++)
 {
-  if (empty($sections[$i]) or $sections[$i]=='..')
+  if (empty($sections[$i]))
   {
     unset($sections[$i]);
     $i--;
+    continue;
+  }
+
+  if ($sections[$i] == '..' or !preg_match('/^[a-zA-Z_\.-]+$/', $sections[$i]))
+  {
+    die('invalid section token ['.htmlentities($sections[$i]).']');
   }
 }
 
```
