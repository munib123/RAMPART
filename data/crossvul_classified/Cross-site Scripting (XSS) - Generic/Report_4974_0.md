# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4974_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4974_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 50-80 of the vulnerable file.

            $_REQUEST['image'],
            /*overload*/mb_strpos($_REQUEST['image'], ',') + 1
        );
        $data = base64_decode($data);
    } else {
        $data = $_REQUEST['image'];
    }

    /* Send download header */
    PMA_downloadHeader(
        $filename,
        $_REQUEST['type'],
        /*overload*/mb_strlen($data)
    );

    /* Send data */
    echo $data;

} else if (isset($_REQUEST['monitorconfig'])) {
    /* For monitor chart config export */
    PMA_downloadHeader('monitor.cfg', 'application/force-download');
    echo urldecode($_REQUEST['monitorconfig']);

} else if (isset($_REQUEST['import'])) {
    /* For monitor chart config import */
    header('Content-type: text/plain');
    if (!file_exists($_FILES['file']['tmp_name'])) {
        exit();
    }
    echo file_get_contents($_FILES['file']['tmp_name']);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,12 +67,16 @@
 
 } else if (isset($_REQUEST['monitorconfig'])) {
     /* For monitor chart config export */
-    PMA_downloadHeader('monitor.cfg', 'application/force-download');
+    PMA_downloadHeader('monitor.cfg', 'application/json; charset=UTF-8');
+    header('X-Content-Type-Options: nosniff');
+
     echo urldecode($_REQUEST['monitorconfig']);
 
 } else if (isset($_REQUEST['import'])) {
     /* For monitor chart config import */
-    header('Content-type: text/plain');
+    header('Content-Type: application/json; charset=UTF-8');
+    header('X-Content-Type-Options: nosniff');
+
     if (!file_exists($_FILES['file']['tmp_name'])) {
         exit();
     }
```
