# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5148_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5148_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 46-86 of the vulnerable file.

    <html lang="en" dir="ltr">
    <head>
    <link rel="icon" href="../favicon.ico" type="image/x-icon" />
    <link rel="shortcut icon" href="../favicon.ico" type="image/x-icon" />
    <meta charset="utf-8" />
    <title>phpMyAdmin OpenID signon example</title>
    </head>
    <body>
    <?php
    if (isset($_SESSION) && isset($_SESSION['PMA_single_signon_error_message'])) {
        echo '<p class="error">' , $_SESSION['PMA_single_signon_message'] , '</p>';
        unset($_SESSION['PMA_single_signon_message']);
    }
    echo $contents;
    ?>
    </body>
    </html>
    <?php
}

/* Need to have cookie visible from parent directory */
session_set_cookie_params(0, '/', '', false);
/* Create signon session */
$session_name = 'SignonSession';
session_name($session_name);
session_start();

// Determine realm and return_to
$base = 'http';
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
    $base .= 's';
}
$base .= '://' . $_SERVER['SERVER_NAME'] . ':' . $_SERVER['SERVER_PORT'];

$realm = $base . '/';
$returnTo = $base . dirname($_SERVER['PHP_SELF']);
if ($returnTo[mb_strlen($returnTo) - 1] != '/') {
    $returnTo .= '/';
}
$returnTo .= 'openid.php';

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,6 +63,16 @@
     <?php
 }
 
+function Die_error($e)
+{
+    $contents = "<div class='relyingparty_results'>\n";
+    $contents .= "<pre>" . htmlspecialchars($e->getMessage()) . "</pre>\n";
+    $contents .= "</div class='relyingparty_results'>";
+    Show_page($contents);
+    exit;
+}
+
+
 /* Need to have cookie visible from parent directory */
 session_set_cookie_params(0, '/', '', false);
 /* Create signon session */
@@ -110,11 +120,7 @@
 try {
     $o = new OpenID_RelyingParty($returnTo, $realm, $identifier);
 } catch (Exception $e) {
-    $contents = "<div class='relyingparty_results'>\n";
-    $contents .= "<pre>" . htmlspecialchars($e->getMessage()) . "</pre>\n";
-    $contents .= "</div class='relyingparty_results'>";
-    Show_page($contents);
-    exit;
+    Die_error($e);
 }
 
 /* Redirect to OpenID provider */
@@ -122,11 +128,7 @@
     try {
         $authRequest = $o->prepare();
     } catch (Exception $e) {
-        $contents = "<div class='relyingparty_results'>\n";
-        $contents .= "<pre>" . htmlspecialchars($e->getMessage()) . "</pre>\n";
-        $contents .= "</div class='relyingparty_results'>";
-        Show_page($contents);
-        exit;
+        Die_error($e);
     }
 
     $url = $authRequest->getAuthorizeURL();
@@ -143,7 +145,11 @@
     }
 
     /* Check reply */
-    $message = new OpenID_Message($queryString, OpenID_Message::FORMAT_HTTP);
+    try {
+        $message = new OpenID_Message($queryString, OpenID_Message::FORMAT_HTTP);
+    } catch (Exception $e) {
+        Die_error($e);
+    }
 
     $id = $message->get('openid.claimed_id');
 
```
