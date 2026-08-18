# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3157_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3157_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 6-46 of the vulnerable file.

// | http://www.PhreeSoft.com                                        |
// +-----------------------------------------------------------------+
// | This program is free software: you can redistribute it and/or   |
// | modify it under the terms of the GNU General Public License as  |
// | published by the Free Software Foundation, either version 3 of  |
// | the License, or any later version.                              |
// |                                                                 |
// | This program is distributed in the hope that it will be useful, |
// | but WITHOUT ANY WARRANTY; without even the implied warranty of  |
// | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the   |
// | GNU General Public License for more details.                    |
// +-----------------------------------------------------------------+
//  Path: /modules/shipping/methods/ups/label_mgr/js_include.php
//

?>
<script type="text/javascript">
<!--
// pass any php variables generated during pre-process that are used in the javascript functions.
// Include translations here as well.
var formName          = "<?php echo $_GET['form']; ?>"; 
var image_delete_text = '<?php echo TEXT_DELETE; ?>';
var image_delete_msg  = '<?php echo SHIPPING_DELETE_CONFIRM; ?>';
<?php echo js_calendar_init($cal_ship); ?>
<?php echo js_calendar_init($cal_exp); ?>

function init() {
  <?php 
    if (!$error && !$auto_print && ($action == 'label' || $action == 'delete')) {
	  echo '  window.opener.location.reload();' . chr(10);
	  echo '  self.close();' . chr(10);
    } 
    if (!$auto_print) echo '  document.getElementById("wt_1").focus();' . chr(10);
  ?>
}

function check_form() {
  var error = 0;
  var error_message = "<?php echo JS_ERROR; ?>";
  if (!document.getElementById('total_weight').value) {
  	error_message += '<?php echo SHIPPING_ERROR_WEIGHT_ZERO; ?>' + '\n';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,6 @@
 <!--
 // pass any php variables generated during pre-process that are used in the javascript functions.
 // Include translations here as well.
-var formName          = "<?php echo $_GET['form']; ?>"; 
 var image_delete_text = '<?php echo TEXT_DELETE; ?>';
 var image_delete_msg  = '<?php echo SHIPPING_DELETE_CONFIRM; ?>';
 <?php echo js_calendar_init($cal_ship); ?>
```
