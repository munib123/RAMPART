# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in php
**Pair ID:** 185_3
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `185_3`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```php
Lines 11-40 of the vulnerable file.

        }
        session_write_close();
        if (empty($obj)) {
            return null;
        }
        return json_decode($obj);
    }

    public static function saveSessionObject($name, $obj)
    {
        session_start();
        $_SESSION[$name.CLIENT_NAME] = json_encode($obj);
        session_write_close();
    }

    public static function unsetClientSession()
    {
        $names = [
            "user",
            "modulePath",
            "admin_current_profile"
        ];
        session_start();
        setcookie('icehrmLF', '');
        foreach ($names as $name) {
            unset($_SESSION[$name.CLIENT_NAME]);
        }
        session_write_close();
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,8 @@
         $names = [
             "user",
             "modulePath",
-            "admin_current_profile"
+            "admin_current_profile",
+            "csrf-login"
         ];
         session_start();
         setcookie('icehrmLF', '');
```
