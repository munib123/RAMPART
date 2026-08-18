# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3340_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3340_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 25-53 of the vulnerable file.


function md5_128($text)
{
    for ($i = 0; $i < 128; ++$i) {
        $text = md5($text);
    }

    return $text;
}

$username = $_POST['name'];
$password = $_POST['password'];
$res = login($username, $password);
switch ($res) {
    case 0:
        echo 1;
    break;

    case 1:
        $_SESSION['login'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['password'] = md5_128($password);
        echo 2;
    break;

    default:
        echo 0;
    break;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,7 +42,7 @@
 
     case 1:
         $_SESSION['login'] = true;
-        $_SESSION['username'] = $username;
+        $_SESSION['username'] = htmlspecialchars($username);
         $_SESSION['password'] = md5_128($password);
         echo 2;
     break;
```
