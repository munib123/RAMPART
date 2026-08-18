# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3750_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3750_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-35 of the vulnerable file.

* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU AFFERO GENERAL PUBLIC LICENSE for more details.
*  
* You should have received a copy of the GNU Lesser General Public 
* License along with this library.  If not, see <http://www.gnu.org/licenses/>.
* 
*/

//no apps or filesystem
$RUNTIME_NOSETUPFS=true;

 

// Check if we are a user
OCP\JSON::checkLoggedIn();
OCP\JSON::checkAppEnabled('bookmarks');

require_once(OC::$APPSROOT . '/apps/bookmarks/bookmarksHelper.php');
$id = addBookmark($_GET['url'], $_GET['title'], $_GET['tags']);
OCP\JSON::success(array('data' => $id));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,5 +31,5 @@
 OCP\JSON::checkAppEnabled('bookmarks');
 
 require_once(OC::$APPSROOT . '/apps/bookmarks/bookmarksHelper.php');
-$id = addBookmark($_GET['url'], $_GET['title'], $_GET['tags']);
+$id = addBookmark($_POST['url'], $_POST['title'], $_POST['tags']);
 OCP\JSON::success(array('data' => $id));
```
