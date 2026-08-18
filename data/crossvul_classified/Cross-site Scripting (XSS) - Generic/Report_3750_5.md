# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3750_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3750_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 16-50 of the vulnerable file.

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


//Filter for tag?
$filterTag = isset($_GET['tag']) ? htmlspecialchars_decode($_GET['tag']) : false;

$offset = isset($_GET['page']) ? intval($_GET['page']) * 10 : 0;

$sort = isset($_GET['sort']) ? ($_GET['sort']) : 'bookmarks_sorting_recent';
if($sort == 'bookmarks_sorting_clicks') {
	$sqlSortColumn = 'clickcount';
} else {
	$sqlSortColumn = 'id';
}


$bookmarks = OC_Bookmarks_Bookmarks::findBookmarks($offset, $sqlSortColumn, $filterTag, true);

OCP\JSON::success(array('data' => $bookmarks));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -33,11 +33,11 @@
 
 
 //Filter for tag?
-$filterTag = isset($_GET['tag']) ? htmlspecialchars_decode($_GET['tag']) : false;
+$filterTag = isset($_POST['tag']) ? htmlspecialchars_decode($_POST['tag']) : false;
 
-$offset = isset($_GET['page']) ? intval($_GET['page']) * 10 : 0;
+$offset = isset($_POST['page']) ? intval($_POST['page']) * 10 : 0;
 
-$sort = isset($_GET['sort']) ? ($_GET['sort']) : 'bookmarks_sorting_recent';
+$sort = isset($_POST['sort']) ? ($_POST['sort']) : 'bookmarks_sorting_recent';
 if($sort == 'bookmarks_sorting_clicks') {
 	$sqlSortColumn = 'clickcount';
 } else {
```
