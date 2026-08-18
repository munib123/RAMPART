# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 4223_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4223_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

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
class AppController extends Controller
{
    public $defaultModel = '';

    public $debugMode = false;

    public $helpers = array('Utility', 'OrgImg', 'FontAwesome', 'UserName', 'DataPathCollector');

    private $__queryVersion = '106';
    public $pyMispVersion = '2.4.128';
    public $phpmin = '7.2';
    public $phprec = '7.4';
    public $pythonmin = '3.6';
    public $pythonrec = '3.7';
    public $isApiAuthed = false;

    public $baseurl = '';
    public $sql_dump = false;

    private $isRest = null;

    // Used for _isAutomation(), a check that returns true if the controller & action combo matches an action that is a non-xml and non-json automation method
    // This is used to allow authentication via headers for methods not covered by _isRest() - as that only checks for JSON and XML formats
    public $automationArray = array(
        'events' => array('csv', 'nids', 'hids', 'xml', 'restSearch', 'stix', 'updateGraph', 'downloadOpenIOCEvent'),
        'attributes' => array('text', 'downloadAttachment', 'returnAttributes', 'restSearch', 'rpz', 'bro'),
        'objects' => array('restSearch')
    );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,7 +46,7 @@
 
     public $helpers = array('Utility', 'OrgImg', 'FontAwesome', 'UserName', 'DataPathCollector');
 
-    private $__queryVersion = '106';
+    private $__queryVersion = '107';
     public $pyMispVersion = '2.4.128';
     public $phpmin = '7.2';
     public $phprec = '7.4';
```
