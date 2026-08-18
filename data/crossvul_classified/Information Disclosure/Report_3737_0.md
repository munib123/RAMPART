# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 3737_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3737_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 4-43 of the vulnerable file.

 * This file is licensed under the Affero General Public License version 3 or
 * later.
 * See the COPYING-README file.
 */
OCP\App::checkAppEnabled('calendar');

if(substr($_SERVER["REQUEST_URI"],0,strlen(OC::$APPSWEBROOT . '/apps/calendar/caldav.php')) == OC::$APPSWEBROOT . '/apps/calendar/caldav.php'){
	$baseuri = OC::$APPSWEBROOT . '/apps/calendar/caldav.php';
}

// only need authentication apps
$RUNTIME_APPTYPES=array('authentication');
OC_App::loadApps($RUNTIME_APPTYPES);

// Backends
$authBackend = new OC_Connector_Sabre_Auth();
$principalBackend = new OC_Connector_Sabre_Principal();
$caldavBackend    = new OC_Connector_Sabre_CalDAV();

// Root nodes
$collection = new Sabre_CalDAV_Principal_Collection($principalBackend); 
$collection->disableListing = true; // Disable listening

$nodes = array( 
	$collection, 
	new Sabre_CalDAV_CalendarRootNode($principalBackend, $caldavBackend),
	);


// Fire up server
$server = new Sabre_DAV_Server($nodes);
$server->setBaseUri($baseuri);
// Add plugins
$server->addPlugin(new Sabre_DAV_Auth_Plugin($authBackend,'ownCloud'));
$server->addPlugin(new Sabre_CalDAV_Plugin());
$server->addPlugin(new Sabre_DAVACL_Plugin());
$server->addPlugin(new Sabre_DAV_Browser_Plugin(false)); // Show something in the Browser, but no upload

// And off we go!
$server->exec();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,12 +21,15 @@
 $caldavBackend    = new OC_Connector_Sabre_CalDAV();
 
 // Root nodes
-$collection = new Sabre_CalDAV_Principal_Collection($principalBackend); 
-$collection->disableListing = true; // Disable listening
+$Sabre_CalDAV_Principal_Collection = new Sabre_CalDAV_Principal_Collection($principalBackend); 
+$Sabre_CalDAV_Principal_Collection->disableListing = true; // Disable listening
+
+$Sabre_CalDAV_CalendarRootNode = new Sabre_CalDAV_CalendarRootNode($principalBackend, $caldavBackend); 
+$Sabre_CalDAV_CalendarRootNode->disableListing = true; // Disable listening
 
 $nodes = array( 
-	$collection, 
-	new Sabre_CalDAV_CalendarRootNode($principalBackend, $caldavBackend),
+	$Sabre_CalDAV_Principal_Collection, 
+	$Sabre_CalDAV_CalendarRootNode,
 	);
 
 
```
