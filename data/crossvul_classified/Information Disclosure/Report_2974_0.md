# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2974_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2974_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 320-360 of the vulnerable file.

            if (!in_array($entry, $ignore) && is_readable($file)) {
                if (is_dir($file)) {
                    addFolder2zip($zip, $file);
                    continue;
                }

                // Zip!
                $filename = str_replace(array(BT_ROOT, '//'), array('', '/'), $file);
                $zip->addFile($file, $filename);
            }
        }
        closedir($handle);
    }
}

/**
 *
 */
function creer_fichier_zip($folders)
{
    $zipfile = 'archive_site-'.date('Ymd').'-'.substr(md5(rand(10, 99)), 3, 5).'.zip';
    $zip = new ZipArchive;
    if ($zip->open(DIR_BACKUP.$zipfile, ZipArchive::CREATE) === true) {
        foreach ($folders as $folder) {
            addFolder2zip($zip, $folder);
        }
        $zip->close();
        if (is_file(DIR_BACKUP.$zipfile)) {
            return URL_BACKUP.$zipfile;
        }
    }
    return false;
}

/**
 * fabrique le fichier json (très simple en fait)
 */
function creer_fichier_json($arrData)
{
    $path = 'backup-data-'.date('Ymd-His').'.json';
    return (file_put_contents(DIR_BACKUP.$path, json_encode($arrData), LOCK_EX) === false) ? false : URL_BACKUP.$path;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -337,7 +337,9 @@
  */
 function creer_fichier_zip($folders)
 {
-    $zipfile = 'archive_site-'.date('Ymd').'-'.substr(md5(rand(10, 99)), 3, 5).'.zip';
+    // fix on windows server, file can be found using "archiv~1.zip" as file name in URL
+    // $zipfile = 'archive_site-'.date('Ymd').'-'.substr(md5(rand(10, 99)), 3, 5).'.zip';
+    $zipfile = substr(md5(rand(10, 99)), 3, 5).'-archive_site-'.date('Ymd').'.zip';
     $zip = new ZipArchive;
     if ($zip->open(DIR_BACKUP.$zipfile, ZipArchive::CREATE) === true) {
         foreach ($folders as $folder) {
```
