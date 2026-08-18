# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2332_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2332_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 7-48 of the vulnerable file.

|                                                                           |
| Copyright: See the COPYRIGHT.txt file.                                    |
| License: GPLv2 or later, see the LICENSE.txt file.                        |
+---------------------------------------------------------------------------+
*/

require_once MAX_PATH . '/lib/max/Admin/UI/Field.php';

/**
 * NOTE
 *
 * THIS CLASS APPEARS TO BE REDUNDANT
 * phpAds_dbQuery DOES NOT EXIST ANYMORE?
 *
 */

class Admin_UI_PublisherIdField extends Admin_UI_Field
{
    function display()
    {
        global $session, $list_filters;

        if (OA_Permission::isAccount(OA_ACCOUNT_TRAFFICKER))
        {
            echo "<input type='hidden' name='{$this->_name}' value='".OA_Permission::getEntityId()."'>";
        }
        else
        {
        $aPublishers = Admin_UI_PublisherIdField::phpAds_getPublisherArray('name');

        // if no default publisher set, set it to the first id in the array
        // - this is to ensure that we'll know which publisher to filter any other
        // dropdowns by even if no publisher is selected yet
        if (!isset($session['prefs']['GLOBALS']['report_publisher'])) {
            $list_filters['publisher'] = key($aPublishers);
        } else {
            $list_filters['publisher'] = $session['prefs']['GLOBALS']['report_publisher'];

        }

        echo "<input type='hidden' name='submit_type' value=''>";
        echo "<input type='hidden' name='changed_field' value=''>";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,8 +24,6 @@
 {
     function display()
     {
-        global $session, $list_filters;
-
         if (OA_Permission::isAccount(OA_ACCOUNT_TRAFFICKER))
         {
             echo "<input type='hidden' name='{$this->_name}' value='".OA_Permission::getEntityId()."'>";
@@ -34,21 +32,8 @@
         {
         $aPublishers = Admin_UI_PublisherIdField::phpAds_getPublisherArray('name');
 
-        // if no default publisher set, set it to the first id in the array
-        // - this is to ensure that we'll know which publisher to filter any other
-        // dropdowns by even if no publisher is selected yet
-        if (!isset($session['prefs']['GLOBALS']['report_publisher'])) {
-            $list_filters['publisher'] = key($aPublishers);
-        } else {
-            $list_filters['publisher'] = $session['prefs']['GLOBALS']['report_publisher'];
-
-        }
-
-        echo "<input type='hidden' name='submit_type' value=''>";
-        echo "<input type='hidden' name='changed_field' value=''>";
-        echo "<input type='hidden' name='refresh_page' value='".htmlspecialchars($_SERVER['REQUEST_URI'])."'>";
         echo "
-        <select name='{$this->_name}' tabindex='".($this->_tabIndex++)."' onchange=\"form.submit_type.value='change';form.changed_field.value='publisher';submit();\"   >";
+        <select name='{$this->_name}' tabindex='".($this->_tabIndex++)."'>";
         foreach ($aPublishers as $publisherId => $aPublisher) {
             $selected = $publisherId == $this->getValue() ? " selected='selected'" : '';
             echo "
@@ -59,9 +44,6 @@
         }
     }
 
-    /**
-     * @todo Handle cases where user is not Admin, Agency or Advertiser
-     */
     function _getPublisherArray($orderBy = null)
     {
         $conf = $GLOBALS['_MAX']['CONF'];
@@ -75,7 +57,7 @@
                 "SELECT affiliateid,name".
                 " FROM ".$conf['table']['prefix'].$conf['table']['affiliates'].
                 " WHERE agencyid=".OA_Permission::getEntityId();
-        } elseif (OA_Permission::isAccount(OA_ACCOUNT_ADVERTISER)) {
+        } elseif (OA_Permission::isAccount(OA_ACCOUNT_TRAFFICKER)) {
             $query =
                 "SELECT affiliateid,name".
                 " FROM ".$conf['table']['prefix'].$conf['table']['affiliates'].
@@ -92,6 +74,7 @@
 
         return ($affiliateArray);
     }
+
 }
 
 ?>
```
