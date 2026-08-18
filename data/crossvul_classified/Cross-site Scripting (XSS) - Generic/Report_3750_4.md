# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3750_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3750_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 20-44 of the vulnerable file.

* License along with this library.  If not, see <http://www.gnu.org/licenses/>.
* 
*/

//no apps or filesystem
$RUNTIME_NOSETUPFS=true;

 

// Check if we are a user
OCP\JSON::checkLoggedIn();
OCP\JSON::checkAppEnabled('bookmarks');

$query = OCP\DB::prepare("
	UPDATE *PREFIX*bookmarks
	SET clickcount = clickcount + 1
	WHERE user_id = ?
		AND url LIKE ?
	");
	
$params=array(OCP\USER::getUser(), htmlspecialchars_decode($_GET["url"]));
$bookmarks = $query->execute($params);

header( "HTTP/1.1 204 No Content" );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,7 +37,7 @@
 		AND url LIKE ?
 	");
 	
-$params=array(OCP\USER::getUser(), htmlspecialchars_decode($_GET["url"]));
+$params=array(OCP\USER::getUser(), htmlspecialchars_decode($_POST["url"]));
 $bookmarks = $query->execute($params);
 
 header( "HTTP/1.1 204 No Content" );
```
