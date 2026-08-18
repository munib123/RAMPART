# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 5679_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5679_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 2444-2484 of the vulnerable file.

     * TODO: test this bad boy, and hack it to work on HTTPS / FTP / IP addresses
     */
    static function checkUrlFormat($url)
    {
        return preg_match('#^http\\:\\/\\/[a-z0-9\-]+\.([a-z0-9\-]+\.)?[a-z]+#i', $url);
    }

    /* Checks that an email address looks valid
     * TODO: Get the function to check that the email domain is valid, and online
     */
    static function checkEmailFormat($email)
    {
      //  return eregi("^[a-z\'0-9]+([._-][a-z\'0-9]+)*@([a-z0-9]+([._-][a-z0-9]+))+$", $email);
      //  return preg_match("#^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]+$#i", $email);
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    /* Gets the IP address of the visitor, bypassing proxies */
    static function getIp()
    {
        if ( (getenv('HTTP_X_FORWARDED_FOR') != '') && (strtolower(getenv('HTTP_X_FORWARDED_FOR')) != 'unknown')) {
            $iparray = explode(',', getenv('HTTP_X_FORWARDED_FOR'));
            return $iparray[0];
        } elseif (getenv('REMOTE_ADDR') != '') {
            return getenv('REMOTE_ADDR');
        } else {
            return false;
        }
    }

    /* reads the user agent string and gives the browser type - quick and simple detection */
    static function getBrowser()
    {
        static $_browser;

        if (isset($_browser)) return $_browser;

        $version = '';
        $nav = '';
        $browsers = 'mozilla msie gecko firefox konqueror safari netscape navigator opera mosaic lynx amaya omniweb snoopy chrome';
        $browsers = explode(' ', $browsers);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2461,14 +2461,18 @@
     /* Gets the IP address of the visitor, bypassing proxies */
     static function getIp()
     {
+        $ip = false;
         if ( (getenv('HTTP_X_FORWARDED_FOR') != '') && (strtolower(getenv('HTTP_X_FORWARDED_FOR')) != 'unknown')) {
             $iparray = explode(',', getenv('HTTP_X_FORWARDED_FOR'));
-            return $iparray[0];
+            $ip = $iparray[0];
         } elseif (getenv('REMOTE_ADDR') != '') {
-            return getenv('REMOTE_ADDR');
-        } else {
-            return false;
-        }
+            $ip = getenv('REMOTE_ADDR');
+        }
+        /* check IP is valid format */
+        if (preg_match('/\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/', $ip)) {
+        	return $ip;
+        }
+        return false;
     }
 
     /* reads the user agent string and gives the browser type - quick and simple detection */
```
