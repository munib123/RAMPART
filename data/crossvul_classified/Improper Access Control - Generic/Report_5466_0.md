# CrossVul Fix Pair: Improper Access Control in php
**Pair ID:** 5466_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5466_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```php
Lines 14-54 of the vulnerable file.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\DAV\Files;

use OC\AppFramework\Http\Request;
use OC_Template;
use OCP\IRequest;
use Sabre\DAV\Exception;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;

class BrowserErrorPagePlugin extends ServerPlugin {

	/** @var Server */
	private $server;

	/**
	 * This initializes the plugin.
	 *
	 * This function is called by Sabre\DAV\Server, after
	 * addPlugin is called.
	 *
	 * This method should set up the required event subscriptions.
	 *
	 * @param Server $server
	 * @return void
	 */
	function initialize(Server $server) {
		$this->server = $server;
		$server->on('exception', array($this, 'logException'), 1000);
	}

	/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,6 @@
 use Sabre\DAV\ServerPlugin;
 
 class BrowserErrorPagePlugin extends ServerPlugin {
-
 	/** @var Server */
 	private $server;
 
@@ -88,8 +87,7 @@
 
 	/**
 	 * @codeCoverageIgnore
-	 * @param \Exception $ex
-	 * @param int $httpCode
+	 * @param \Exception $exception
 	 * @return bool|string
 	 */
 	public function generateBody(\Exception $exception) {
@@ -109,10 +107,11 @@
 		return $content->fetchPage();
 	}
 
-	/*
+	/**
 	 * @codeCoverageIgnore
 	 */
 	public function sendResponse() {
 		$this->server->sapi->sendResponse($this->server->httpResponse);
+		exit();
 	}
 }
```
