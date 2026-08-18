# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 3737_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3737_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 19-57 of the vulnerable file.

 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

OCP\App::checkAppEnabled('contacts');

if(substr($_SERVER["REQUEST_URI"],0,strlen(OC::$APPSWEBROOT . '/apps/contacts/carddav.php')) == OC::$APPSWEBROOT . '/apps/contacts/carddav.php'){
	$baseuri = OC::$APPSWEBROOT . '/apps/contacts/carddav.php';
}

// only need authentication apps
$RUNTIME_APPTYPES=array('authentication');
OC_App::loadApps($RUNTIME_APPTYPES);

// Backends
$authBackend = new OC_Connector_Sabre_Auth();
$principalBackend = new OC_Connector_Sabre_Principal();
$carddavBackend   = new OC_Connector_Sabre_CardDAV();

// Root nodes
$collection = new Sabre_CalDAV_Principal_Collection($principalBackend); 
$collection->disableListing = true; // Disable listening

$nodes = array( 
	$collection, 
	new Sabre_CardDAV_AddressBookRoot($principalBackend, $carddavBackend),
	);

// Fire up server
$server = new Sabre_DAV_Server($nodes);
$server->setBaseUri($baseuri);
// Add plugins
$server->addPlugin(new Sabre_DAV_Auth_Plugin($authBackend,'ownCloud'));
$server->addPlugin(new Sabre_CardDAV_Plugin());
$server->addPlugin(new Sabre_DAVACL_Plugin());
$server->addPlugin(new Sabre_DAV_Browser_Plugin(false)); // Show something in the Browser, but no upload

// And off we go!
$server->exec();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,12 +36,15 @@
 $carddavBackend   = new OC_Connector_Sabre_CardDAV();
 
 // Root nodes
-$collection = new Sabre_CalDAV_Principal_Collection($principalBackend); 
-$collection->disableListing = true; // Disable listening
+$Sabre_CalDAV_Principal_Collection = new Sabre_CalDAV_Principal_Collection($principalBackend); 
+$Sabre_CalDAV_Principal_Collection->disableListing = true; // Disable listening
+
+$Sabre_CardDAV_AddressBookRoot = new Sabre_CardDAV_AddressBookRoot($principalBackend, $carddavBackend);
+$Sabre_CardDAV_AddressBookRoot->disableListing = true; // Disable listening
 
 $nodes = array( 
-	$collection, 
-	new Sabre_CardDAV_AddressBookRoot($principalBackend, $carddavBackend),
+	$Sabre_CalDAV_Principal_Collection, 
+	$Sabre_CardDAV_AddressBookRoot,
 	);
 
 // Fire up server
```
