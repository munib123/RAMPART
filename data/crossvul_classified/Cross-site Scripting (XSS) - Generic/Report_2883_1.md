# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2883_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2883_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 15-56 of the vulnerable file.

require_once plugin_dir_path(dirname(__FILE__)) . 'about/plugin-notice.php';

global $current_user;
$Date_Time_Helper = new User_Login_History_Date_Time_Helper();
$user_timezone = get_user_meta($current_user->ID, ULH_PLUGIN_OPTION_PREFIX . "user_timezone", TRUE);
if (!$user_timezone) {
    $user_timezone = $Date_Time_Helper->get_default_timezone();
}
$timezones = $Date_Time_Helper->get_timezone_list();
?>
   
<div class="wrap">
    <h1><?php _e('User Login History', 'user-login-history'); ?></h1>
    <div id="poststuff">
        <div class="search-filter">
            <form name="user-login-histoty-search-form" method="get" action="" id="user-login-histoty-search-form">
                <input type="hidden" name="page" value="user-login-history" />
                <table class="wp-list-table widefat fixed striped">
                    <tbody>
                        <tr>
                            <td><input readonly autocomplete="off" placeholder="<?php _e("From", "user-login-history") ?>" id="date_from" name="date_from" value="<?php echo isset($_GET['date_from']) ? $_GET['date_from'] : "" ?>" class="textfield-bg"></td>
                            <td><input readonly autocomplete="off" placeholder="<?php _e("To", "user-login-history") ?>" name="date_to" id="date_to" value="<?php echo isset($_GET['date_to']) ? $_GET['date_to'] : "" ?>" class="textfield-bg"></td>
                            <td>
                                <select class="selectfield-bg" name="date_type" >
                                    <?php
                                    $date_types = array('login' => __("Login", "user-login-history"), 'logout' => __("Logout", "user-login-history"));
                                    foreach ($date_types as $date_type_key => $date_type) {
                                        ?>
                                        <option value="<?php print $date_type_key ?>" <?php selected(isset($_GET['date_type']) ? $_GET['date_type'] : "", $date_type_key); ?>>
                                            <?php echo $date_type ?>
                                        </option>
                                    <?php } ?>
                                </select>
                            </td>
                        </tr>
                    </tbody></table>
                <table class="wp-list-table widefat fixed striped">
                    <tbody>
                        <tr>
                            <td><input placeholder="<?php _e("Enter User Id", "user-login-history") ?>" name="user_id" value="<?php echo isset($_GET['user_id']) ? $_GET['user_id'] : "" ?>" class="textfield-bg"></td>
                            <td><input placeholder="<?php _e("Enter Username", "user-login-history") ?>" name="username" value="<?php echo isset($_GET['username']) ? $_GET['username'] : "" ?>" class="textfield-bg"></td>
                            <td><input placeholder="<?php _e("Enter Country", "user-login-history") ?>" name="country_name" value="<?php echo isset($_GET['country_name']) ? $_GET['country_name'] : "" ?>" class="textfield-bg"></td>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,8 +32,8 @@
                 <table class="wp-list-table widefat fixed striped">
                     <tbody>
                         <tr>
-                            <td><input readonly autocomplete="off" placeholder="<?php _e("From", "user-login-history") ?>" id="date_from" name="date_from" value="<?php echo isset($_GET['date_from']) ? $_GET['date_from'] : "" ?>" class="textfield-bg"></td>
-                            <td><input readonly autocomplete="off" placeholder="<?php _e("To", "user-login-history") ?>" name="date_to" id="date_to" value="<?php echo isset($_GET['date_to']) ? $_GET['date_to'] : "" ?>" class="textfield-bg"></td>
+                            <td><input readonly autocomplete="off" placeholder="<?php _e("From", "user-login-history") ?>" id="date_from" name="date_from" value="<?php echo isset($_GET['date_from']) ? esc_html($_GET['date_from']) : "" ?>" class="textfield-bg"></td>
+                            <td><input readonly autocomplete="off" placeholder="<?php _e("To", "user-login-history") ?>" name="date_to" id="date_to" value="<?php echo isset($_GET['date_to']) ? esc_html($_GET['date_to']) : "" ?>" class="textfield-bg"></td>
                             <td>
                                 <select class="selectfield-bg" name="date_type" >
                                     <?php
@@ -51,12 +51,12 @@
                 <table class="wp-list-table widefat fixed striped">
                     <tbody>
                         <tr>
-                            <td><input placeholder="<?php _e("Enter User Id", "user-login-history") ?>" name="user_id" value="<?php echo isset($_GET['user_id']) ? $_GET['user_id'] : "" ?>" class="textfield-bg"></td>
-                            <td><input placeholder="<?php _e("Enter Username", "user-login-history") ?>" name="username" value="<?php echo isset($_GET['username']) ? $_GET['username'] : "" ?>" class="textfield-bg"></td>
-                            <td><input placeholder="<?php _e("Enter Country", "user-login-history") ?>" name="country_name" value="<?php echo isset($_GET['country_name']) ? $_GET['country_name'] : "" ?>" class="textfield-bg"></td>
-                            <td><input placeholder="<?php _e("Enter Browser", "user-login-history") ?>" name="browser" value="<?php echo isset($_GET['browser']) ? $_GET['browser'] : "" ?>" class="textfield-bg"></td>
-                            <td><input placeholder="<?php _e("Enter Operating System", "user-login-history") ?>" name="operating_system" value="<?php echo isset($_GET['operating_system']) ? $_GET['operating_system'] : "" ?>" class="textfield-bg"></td>
-                            <td><input placeholder="<?php _e("Enter IP Address", "user-login-history") ?>" name="ip_address" value="<?php echo isset($_GET['ip_address']) ? $_GET['ip_address'] : "" ?>" class="textfield-bg"></td>
+                            <td><input placeholder="<?php _e("Enter User Id", "user-login-history") ?>" name="user_id" value="<?php echo isset($_GET['user_id']) ? esc_html($_GET['user_id']) : "" ?>" class="textfield-bg"></td>
+                            <td><input placeholder="<?php _e("Enter Username", "user-login-history") ?>" name="username" value="<?php echo isset($_GET['username']) ? esc_html($_GET['username']) : "" ?>" class="textfield-bg"></td>
+                            <td><input placeholder="<?php _e("Enter Country", "user-login-history") ?>" name="country_name" value="<?php echo isset($_GET['country_name']) ? esc_html($_GET['country_name']) : "" ?>" class="textfield-bg"></td>
+                            <td><input placeholder="<?php _e("Enter Browser", "user-login-history") ?>" name="browser" value="<?php echo isset($_GET['browser']) ? esc_html($_GET['browser']) : "" ?>" class="textfield-bg"></td>
+                            <td><input placeholder="<?php _e("Enter Operating System", "user-login-history") ?>" name="operating_system" value="<?php echo isset($_GET['operating_system']) ? esc_html($_GET['operating_system']) : "" ?>" class="textfield-bg"></td>
+                            <td><input placeholder="<?php _e("Enter IP Address", "user-login-history") ?>" name="ip_address" value="<?php echo isset($_GET['ip_address']) ? esc_html($_GET['ip_address']) : "" ?>" class="textfield-bg"></td>
                         </tr>
                     </tbody></table>
                 <table class="wp-list-table widefat fixed striped">
```
