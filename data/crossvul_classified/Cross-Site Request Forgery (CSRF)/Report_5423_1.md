# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in php
**Pair ID:** 5423_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5423_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```php
Lines 29-69 of the vulnerable file.

class MAX_Admin_Inventory_TrackerAppend
{
    /* @var MAX_Dal_TrackerTags */
    var $_dal;

    var $_cycle = 0;

    var $advertiser_id;
    var $tracker_id;
    var $codes;
    var $showReminder;
    var $assetPath;

    /**
     * PHP5-style constructor
     */
    function __construct()
    {
        $this->_useDefaultDal();

        $this->advertiser_id = MAX_getValue('clientid', 0);
        $this->tracker_id    = MAX_getValue('trackerid', 0);
        $this->assetPath 	 = OX::assetPath();
        $this->showReminder  = false;
    }

    function _useDefaultDal()
    {
        $oServiceLocator =& OA_ServiceLocator::instance();
        $dal =& $oServiceLocator->get('MAX_Dal_Inventory_Trackers');
        if (!$dal) {
            $dal = new MAX_Dal_Inventory_Trackers();
        }
        $this->_dal =& $dal;
    }

    function cycleRow($class)
    {
        return trim($class.(($this->_cycle++ % 2) ? ' light' : ' dark'));
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,7 @@
     {
         $this->_useDefaultDal();
 
+        $this->csrf_token    = phpAds_SessionGetToken();
         $this->advertiser_id = MAX_getValue('clientid', 0);
         $this->tracker_id    = MAX_getValue('trackerid', 0);
         $this->assetPath 	 = OX::assetPath();
```
