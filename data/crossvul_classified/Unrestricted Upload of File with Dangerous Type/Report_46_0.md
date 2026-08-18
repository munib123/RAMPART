# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 46_0
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `46_0`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 4943-4962 of the vulnerable file.

*/
function isJson($str) {
    $json = json_decode($str);
    return $json && $str != $json;
}

/**
* Check if array is associative
*
* @param array $array
* @return bool
*/
function isAssociativeArray($array){
    foreach ($array as $key => $value) {
        if (is_string($key)) {
            return true;
        }
    }
    return false;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4960,3 +4960,40 @@
     }
     return false;
 }
+
+/**
+ * Test if a given zip file is Zip Bomb
+ * see comment here : http://php.net/manual/en/function.zip-entry-filesize.php
+ * @param string $zip_filename
+ * @return int
+ */
+function isZipBomb($zip_filename)
+{
+    return ( get_zip_originalsize($zip_filename) >  getMaximumFileUploadSize() );
+}
+
+/**
+ * Get the original size of a zip archive to prevent Zip Bombing
+ * see comment here : http://php.net/manual/en/function.zip-entry-filesize.php
+ * @param string $filename
+ * @return int
+ */
+function get_zip_originalsize($filename) {
+
+    if ( function_exists ('zip_entry_filesize') ){
+        $size = 0;
+        $resource = zip_open($filename);
+        while ($dir_resource = zip_read($resource)) {
+            $size += zip_entry_filesize($dir_resource);
+        }
+        zip_close($resource);
+
+        return $size;
+    }else{
+        if ( YII_DEBUG ){
+            Yii::app()->setFlashMessage(gT("Warning! php zip extension is not installed on your server. You're not protected from Zip Bomb attaacks."), 'error');
+        }
+    }
+
+    return -1;
+}
```
