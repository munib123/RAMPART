# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 5143_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5143_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 81-121 of the vulnerable file.

$returnTo = $base . dirname($_SERVER['PHP_SELF']);
if ($returnTo[mb_strlen($returnTo) - 1] != '/') {
    $returnTo .= '/';
}
$returnTo .= 'openid.php';

/* Display form */
if (!count($_GET) && !count($_POST) || isset($_GET['phpMyAdmin'])) {
    /* Show simple form */
    $content = '<form action="openid.php" method="post">
OpenID: <input type="text" name="identifier" /><br />
<input type="submit" name="start" />
</form>
</body>
</html>';
    Show_page($content);
    exit;
}

/* Grab identifier */
if (isset($_POST['identifier'])) {
    $identifier = $_POST['identifier'];
} else if (isset($_SESSION['identifier'])) {
    $identifier = $_SESSION['identifier'];
} else {
    $identifier = null;
}

/* Create OpenID object */
try {
    $o = new OpenID_RelyingParty($returnTo, $realm, $identifier);
} catch (OpenID_Exception $e) {
    $contents = "<div class='relyingparty_results'>\n";
    $contents .= "<pre>" . $e->getMessage() . "</pre>\n";
    $contents .= "</div class='relyingparty_results'>";
    Show_page($contents);
    exit;
}

/* Redirect to OpenID provider */
if (isset($_POST['start'])) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,9 +98,9 @@
 }
 
 /* Grab identifier */
-if (isset($_POST['identifier'])) {
+if (isset($_POST['identifier']) && is_string($_POST['identifier'])) {
     $identifier = $_POST['identifier'];
-} else if (isset($_SESSION['identifier'])) {
+} else if (isset($_SESSION['identifier']) && is_string($_SESSION['identifier'])) {
     $identifier = $_SESSION['identifier'];
 } else {
     $identifier = null;
@@ -109,7 +109,7 @@
 /* Create OpenID object */
 try {
     $o = new OpenID_RelyingParty($returnTo, $realm, $identifier);
-} catch (OpenID_Exception $e) {
+} catch (Exception $e) {
     $contents = "<div class='relyingparty_results'>\n";
     $contents .= "<pre>" . $e->getMessage() . "</pre>\n";
     $contents .= "</div class='relyingparty_results'>";
```
