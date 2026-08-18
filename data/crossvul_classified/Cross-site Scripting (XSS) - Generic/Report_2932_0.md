# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2932_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2932_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.


/**
 * Application Controller
 *
 * Add your application-wide methods in the class below, your controllers
 * will inherit them.
 *
 * @package       app.Controller
 * @link http://book.cakephp.org/2.0/en/controllers.html#the-app-controller
 *
 * @throws ForbiddenException // TODO Exception
 */
class AppController extends Controller {

	public $defaultModel = '';

	public $debugMode = false;

	public $helpers = array('Utility');

	private $__queryVersion = '23';
	public $pyMispVersion = '2.4.82';
	public $phpmin = '5.6.5';
	public $phprec = '7.0.16';

	// Used for _isAutomation(), a check that returns true if the controller & action combo matches an action that is a non-xml and non-json automation method
	// This is used to allow authentication via headers for methods not covered by _isRest() - as that only checks for JSON and XML formats
	public $automationArray = array(
		'events' => array('csv', 'nids', 'hids', 'xml', 'restSearch', 'stix', 'updateGraph', 'downloadOpenIOCEvent'),
		'attributes' => array('text', 'downloadAttachment', 'returnAttributes', 'restSearch', 'rpz', 'bro'),
	);

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);

		$name = get_class($this);
		$name = str_replace('sController', '', $name);
		$name = str_replace('Controller', '', $name);
		$this->defaultModel = $name;
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,7 @@
 
 	public $helpers = array('Utility');
 
-	private $__queryVersion = '23';
+	private $__queryVersion = '24';
 	public $pyMispVersion = '2.4.82';
 	public $phpmin = '5.6.5';
 	public $phprec = '7.0.16';
```
