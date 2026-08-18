# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 3896_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3896_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 244-284 of the vulnerable file.

        }

        $web = \Web::instance();

        $f3->set("UPLOADS", 'uploads/avatars/');
        if (!is_dir($f3->get("UPLOADS"))) {
            mkdir($f3->get("UPLOADS"), 0777, true);
        }
        $overwrite = true;
        $slug = true;

        // Make a good name
        $parts = pathinfo($_FILES['avatar']['name']);
        $_FILES['avatar']['name'] = $user->id . "-" . substr(uniqid(), 0, 4)  . "." . $parts["extension"];
        $f3->set("avatar_filename", $_FILES['avatar']['name']);

        // Verify file is an image
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $allowedTypes = ['image/jpeg', 'image/gif', 'image/png', 'image/bmp'];
        if (!in_array(finfo_file($finfo, $_FILES['avatar']['tmp_name']), $allowedTypes)) {
            $f3->error(400);
            return;
        }
        finfo_close($finfo);

        $web->receive(
            function ($file) use ($f3, $user) {
                if ($file['size'] > $f3->get("files.maxsize")) {
                    return false;
                }

                $user->avatar_filename = $f3->get("avatar_filename");
                $user->save();
                return true;
            },
            $overwrite,
            $slug
        );

        // Clear cached profile picture data
        $cache = \Cache::instance();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -261,7 +261,7 @@
         $finfo = finfo_open(FILEINFO_MIME_TYPE);
         $allowedTypes = ['image/jpeg', 'image/gif', 'image/png', 'image/bmp'];
         if (!in_array(finfo_file($finfo, $_FILES['avatar']['tmp_name']), $allowedTypes)) {
-            $f3->error(400);
+            $f3->error(415);
             return;
         }
         finfo_close($finfo);
```
