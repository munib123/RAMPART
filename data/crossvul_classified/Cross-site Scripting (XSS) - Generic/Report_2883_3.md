# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2883_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2883_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-22 of the vulnerable file.

<?php
global $wpdb, $current_user;
if (!$current_user->ID) {
    _e('Error- Unable to find user id. Please login.', 'user-login-history');
    return;
}
$unknown = __('Unknown', 'user-login-history');
$options = get_option(ULH_PLUGIN_OPTION_PREFIX . 'frontend_fields');
if (!$options) {
    _e('No Fields has been selected from admin panel. Please select fields from frontend option tab of the plugin setting.', 'user-login-history');
    return;
}

$options['old_role'] = isset($options['old_role']) ? $options['old_role'] : FALSE;
$options['ip_address'] = isset($options['ip_address']) ? $options['ip_address'] : FALSE;
$options['browser'] = isset($options['browser']) ? $options['browser'] : FALSE;
$options['operating_system'] = isset($options['operating_system']) ? $options['operating_system'] : FALSE;
$options['country'] = isset($options['country']) ? $options['country'] : FALSE;
$options['last_seen'] = isset($options['last_seen']) ? $options['last_seen'] : FALSE;
$options['login'] = isset($options['login']) ? $options['login'] : FALSE;
$options['logout'] = isset($options['logout']) ? $options['logout'] : FALSE;
$options['duration'] = isset($options['duration']) ? $options['duration'] : FALSE;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,6 @@
 <?php
-global $wpdb, $current_user;
+
+global $wpdb, $current_user,$wp;
 if (!$current_user->ID) {
     _e('Error- Unable to find user id. Please login.', 'user-login-history');
     return;
@@ -54,12 +55,12 @@
 $logins = $paginations['rows'];
 $timezones = User_Login_History_Date_Time_Helper :: get_timezone_list();
 ?>
-<form name="user_login_history_public_filter_form" method="get" action="<?php echo $_SERVER['REQUEST_URI'] ?>">
+<form name="user_login_history_public_filter_form" method="get" action="">
     <table width="100%" class="form-table">
         <tbody>
             <tr>
-                <td><input readonly="readonly" autocomplete="off" placeholder="From" id="date_from" name="date_from" value="<?php echo isset($_GET['date_from']) ? $_GET['date_from'] : "" ?>" class="textfield-bg"></td>
-                <td><input readonly="readonly" autocomplete="off" placeholder="To" name="date_to" id="date_to" value="<?php echo isset($_GET['date_to']) ? $_GET['date_to'] : "" ?>" class="textfield-bg"></td>
+                <td><input readonly="readonly" autocomplete="off" placeholder="From" id="date_from" name="date_from" value="<?php echo isset($_GET['date_from']) ? esc_html($_GET['date_from']) : "" ?>" class="textfield-bg"></td>
+                <td><input readonly="readonly" autocomplete="off" placeholder="To" name="date_to" id="date_to" value="<?php echo isset($_GET['date_to']) ? esc_html($_GET['date_to']) : "" ?>" class="textfield-bg"></td>
                 <td>
                     <select name="date_type" class="selectfield-bg">
                         <?php
@@ -78,7 +79,10 @@
         <tbody>
             <tr>
                 <td>
-                    <input type="submit" value="Filter" name="ulh_public_filter_form_submit" class="go-bg">
+                    <input type="submit" value="<?php _e('FILTER', 'user-login-history') ?>" name="ulh_public_filter_form_submit" class="go-bg">
+                </td>
+                <td>
+                   <?php echo "<a class='ulh-cancel-link' href=".(explode('?',  home_url( $wp->request ), 2)[0])."> ".__('RESET', 'user-login-history')."</a>";?>
                 </td>
             </tr>
         </tbody></table>
```
