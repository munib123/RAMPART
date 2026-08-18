# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2883_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2883_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 164-204 of the vulnerable file.

            '/windows nt 6.2/i' => 'Windows 8',
            '/windows nt 6.1/i' => 'Windows 7',
            '/windows nt 6.0/i' => 'Windows Vista',
            '/windows nt 5.2/i' => 'Windows Server 2003/XP x64',
            '/windows nt 5.1/i' => 'Windows XP',
            '/windows xp/i' => 'Windows XP',
            '/windows nt 5.0/i' => 'Windows 2000',
            '/windows me/i' => 'Windows ME',
            '/win98/i' => 'Windows 98',
            '/win95/i' => 'Windows 95',
            '/win16/i' => 'Windows 3.11',
            '/macintosh|mac os x/i' => 'Mac OS X',
            '/mac_powerpc/i' => 'Mac OS 9',
            '/linux/i' => 'Linux',
            '/ubuntu/i' => 'Ubuntu',
            '/iphone/i' => 'iPhone',
            '/ipod/i' => 'iPod',
            '/ipad/i' => 'iPad',
            '/android/i' => 'Android',
            '/blackberry/i' => 'BlackBerry',
            '/webos/i' => 'Mobile'
        );

        foreach ($os_array as $regex => $value) {

            if (preg_match($regex, $user_agent)) {
                $os_platform = $value;
            }
        }

        return $os_platform;
    }

    /**
     * Get geo location.
     *
     * @since    1.3
     * @return string
     */
    private function get_geo_location() {
        $client = @$_SERVER['HTTP_CLIENT_IP'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,7 +181,8 @@
             '/ipad/i' => 'iPad',
             '/android/i' => 'Android',
             '/blackberry/i' => 'BlackBerry',
-            '/webos/i' => 'Mobile'
+            '/webos/i' => 'Mobile',
+            '/cros/i' => 'Chrome'
         );
 
         foreach ($os_array as $regex => $value) {
@@ -337,10 +338,10 @@
         $operating_system = $this->get_operating_system();
 
         $geo_location = $this->get_geo_location();
-        $country_name = $geo_location->geoplugin_countryName ? $geo_location->geoplugin_countryName : $unknown;
-        $country_code = $geo_location->geoplugin_countryCode ? $geo_location->geoplugin_countryCode : $unknown;
-        $lat = $geo_location->geoplugin_latitude ? $geo_location->geoplugin_latitude : 0;
-        $long = $geo_location->geoplugin_longitude ? $geo_location->geoplugin_longitude : 0;
+        $country_name = isset($geo_location->geoplugin_countryName) ? $geo_location->geoplugin_countryName : $unknown;
+        $country_code = isset($geo_location->geoplugin_countryCode) ? $geo_location->geoplugin_countryCode : $unknown;
+        $lat = isset($geo_location->geoplugin_latitude) ? $geo_location->geoplugin_latitude : 0;
+        $long = isset($geo_location->geoplugin_longitude )? $geo_location->geoplugin_longitude : 0;
 
         if ($lat != 0 && $long != 0 && $country_code != $unknown) {
             $user_timezone = $this->get_nearest_timezone($lat, $long, $country_code);
@@ -369,9 +370,8 @@
 
         $wpdb->insert($table, $data);
         if ("" != $wpdb->last_error) {
-            ini_set('error_log', WP_CONTENT_DIR . '/debug-user-login-history.log');
-            error_log("last error:" . $wpdb->last_error);
-            error_log("last query:" . $wpdb->last_query);
+           User_Login_History_Error_Handler::error_log("last error:" . $wpdb->last_error. " last query:" . $wpdb->last_query);
+            return;
         }
 
         //save user time zone in user_meta table
@@ -400,13 +400,10 @@
         $wpdb->query($sql);
         
          if ("" != $wpdb->last_error) {
-            ini_set('error_log', WP_CONTENT_DIR . '/debug-user-login-history.log');
-            error_log("last error:" . $wpdb->last_error);
-            error_log("last query:" . $wpdb->last_query);
+          User_Login_History_Error_Handler::error_log("last error:" . $wpdb->last_error. " last query:" . $wpdb->last_query);
         }
         
-        //unset session for this plugin after user gets logged out.
-        unset($_SESSION[$this->name]);
+        session_destroy();
     }
 
     /**
@@ -453,9 +450,7 @@
         $sql = " update $table set time_last_seen='$current_date' where id=$last_id ";
         $wpdb->query($sql);
            if ("" != $wpdb->last_error) {
-            ini_set('error_log', WP_CONTENT_DIR . '/debug-user-login-history.log');
-            error_log("last error:" . $wpdb->last_error);
-            error_log("last query:" . $wpdb->last_query);
+          User_Login_History_Error_Handler::error_log("last error:" . $wpdb->last_error. " last query:" . $wpdb->last_query);
         }
     }
 
```
