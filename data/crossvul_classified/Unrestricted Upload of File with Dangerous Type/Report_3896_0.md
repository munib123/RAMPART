# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 3896_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3896_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 1170-1210 of the vulnerable file.

        $issue = new \Model\Issue;
        $issue->load(array("id=? AND deleted_date IS NULL", $f3->get("POST.issue_id")));
        if (!$issue->id) {
            $f3->error(404);
            return;
        }

        $web = \Web::instance();

        $f3->set("UPLOADS", "uploads/".date("Y")."/".date("m")."/");
        if (!is_dir($f3->get("UPLOADS"))) {
            mkdir($f3->get("UPLOADS"), 0777, true);
        }
        $overwrite = false; // set to true to overwrite an existing file; Default: false
        $slug = true; // rename file to filesystem-friendly version

        // Make a good name
        $orig_name = preg_replace("/[^A-Z0-9._-]/i", "_", $_FILES['attachment']['name']);
        $_FILES['attachment']['name'] = time() . "_" . $orig_name;

        $i = 0;
        $parts = pathinfo($_FILES['attachment']['name']);
        while (file_exists($f3->get("UPLOADS") . $_FILES['attachment']['name'])) {
            $i++;
            $_FILES['attachment']['name'] = $parts["filename"] . "-" . $i . "." . $parts["extension"];
        }

        $web->receive(
            function ($file) use ($f3, $orig_name, $user_id, $issue) {
                if ($file['size'] > $f3->get("files.maxsize")) {
                    return false;
                }

                $newfile = new \Model\Issue\File;
                $newfile->issue_id = $issue->id;
                $newfile->user_id = $user_id;
                $newfile->filename = $orig_name;
                $newfile->disk_filename = $file['name'];
                $newfile->disk_directory = $f3->get("UPLOADS");
                $newfile->filesize = $file['size'];
                $newfile->content_type = $file['type'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1187,6 +1187,14 @@
         $orig_name = preg_replace("/[^A-Z0-9._-]/i", "_", $_FILES['attachment']['name']);
         $_FILES['attachment']['name'] = time() . "_" . $orig_name;
 
+        // Blacklist certain file types
+        if ($f3->get('security.file_blacklist')) {
+            if (preg_match($f3->get('security.file_blacklist'), $orig_name)) {
+                $f3->error(415);
+                return;
+            }
+        }
+
         $i = 0;
         $parts = pathinfo($_FILES['attachment']['name']);
         while (file_exists($f3->get("UPLOADS") . $_FILES['attachment']['name'])) {
```
