# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5149_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5149_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 94-134 of the vulnerable file.

</body>
</html>';
    Show_page($content);
    exit;
}

/* Grab identifier */
if (isset($_POST['identifier']) && is_string($_POST['identifier'])) {
    $identifier = $_POST['identifier'];
} else if (isset($_SESSION['identifier']) && is_string($_SESSION['identifier'])) {
    $identifier = $_SESSION['identifier'];
} else {
    $identifier = null;
}

/* Create OpenID object */
try {
    $o = new OpenID_RelyingParty($returnTo, $realm, $identifier);
} catch (Exception $e) {
    $contents = "<div class='relyingparty_results'>\n";
    $contents .= "<pre>" . $e->getMessage() . "</pre>\n";
    $contents .= "</div class='relyingparty_results'>";
    Show_page($contents);
    exit;
}

/* Redirect to OpenID provider */
if (isset($_POST['start'])) {
    try {
        $authRequest = $o->prepare();
    } catch (OpenID_Exception $e) {
        $contents = "<div class='relyingparty_results'>\n";
        $contents .= "<pre>" . $e->getMessage() . "</pre>\n";
        $contents .= "</div class='relyingparty_results'>";
        Show_page($contents);
        exit;
    }

    $url = $authRequest->getAuthorizeURL();

    header("Location: $url");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -111,7 +111,7 @@
     $o = new OpenID_RelyingParty($returnTo, $realm, $identifier);
 } catch (Exception $e) {
     $contents = "<div class='relyingparty_results'>\n";
-    $contents .= "<pre>" . $e->getMessage() . "</pre>\n";
+    $contents .= "<pre>" . htmlspecialchars($e->getMessage()) . "</pre>\n";
     $contents .= "</div class='relyingparty_results'>";
     Show_page($contents);
     exit;
@@ -121,9 +121,9 @@
 if (isset($_POST['start'])) {
     try {
         $authRequest = $o->prepare();
-    } catch (OpenID_Exception $e) {
+    } catch (Exception $e) {
         $contents = "<div class='relyingparty_results'>\n";
-        $contents .= "<pre>" . $e->getMessage() . "</pre>\n";
+        $contents .= "<pre>" . htmlspecialchars($e->getMessage()) . "</pre>\n";
         $contents .= "</div class='relyingparty_results'>";
         Show_page($contents);
         exit;
```
