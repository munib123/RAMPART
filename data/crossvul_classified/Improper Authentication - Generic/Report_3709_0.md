# CrossVul Fix Pair: Improper Authentication in php
**Pair ID:** 3709_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3709_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```php
Lines 1-23 of the vulnerable file.

<?php defined('SYSPATH') or die('No direct script access.');
/**
 * This class handles GET request for KML via the API.
 *
 * @version 25 - Emmanuel Kala 2010-10-27
 *
 * PHP version 5
 * LICENSE: This source file is subject to LGPL license
 * that is available through the world-wide-web at the following URI:
 * http://www.gnu.org/copyleft/lesser.html
 * @author     Ushahidi Team <team@ushahidi.com>
 * @package    Ushahidi - http://source.ushahididev.com
 * @module     API Controller
 * @copyright  Ushahidi - http://www.ushahidi.com
 * @license    http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License (LGPL)
 */
class Email_Api_Object extends Api_Object_Core {

    public function __construct($api_service)
    {
        parent::__construct($api_service);
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 <?php defined('SYSPATH') or die('No direct script access.');
 /**
- * This class handles GET request for KML via the API.
+ * This class handles GET request for Email via the API.
  *
  * @version 25 - Emmanuel Kala 2010-10-27
  *
@@ -26,6 +26,13 @@
      */
     public function perform_task()
     {
+			// Authenticate the user
+			if ( ! $this->api_service->_login(TRUE))
+			{
+				$this->set_error_message($this->response(2));
+				return;
+			}
+			
         $this->_list_all_email_msgs();
     }
 
@@ -34,6 +41,13 @@
      */
     public function email_action()
     {
+			// Authenticate the user
+			if ( ! $this->api_service->_login(TRUE))
+			{
+				$this->set_error_message($this->response(2));
+				return;
+			}
+			
         if ( ! $this->api_service->verify_array_index($this->request, 'action'))
         {
             $this->set_error_message(array(
@@ -159,7 +173,7 @@
                     //email id doesn't exist in DB
                     //TODO i18nize the string
                     $this->error_messages .= "Email ID does not exist.";
-                    $this->ret_value = 1;
+                    $ret_value = 1;
 
                 }
             }
```
