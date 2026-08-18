# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 3739_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3739_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 12-35 of the vulnerable file.

* version 3 of the License, or any later version.
* 
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
$id = addBookmark($_POST['url'], $_POST['title'], $_POST['tags']);
OCP\JSON::success(array('data' => $id));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,6 +29,7 @@
 // Check if we are a user
 OCP\JSON::checkLoggedIn();
 OCP\JSON::checkAppEnabled('bookmarks');
+OCP\JSON::callCheck();
 
 require_once(OC::$APPSROOT . '/apps/bookmarks/bookmarksHelper.php');
 $id = addBookmark($_POST['url'], $_POST['title'], $_POST['tags']);
```
