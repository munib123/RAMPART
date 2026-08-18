# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 47_4
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `47_4`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 4944-4984 of the vulnerable file.

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

/**
 * Test if a given zip file is Zip Bomb
 * see comment here : http://php.net/manual/en/function.zip-entry-filesize.php
 * @param string $zip_filename
 * @return int
 */
function isZipBomb($zip_filename)
{
    return ( get_zip_originalsize($zip_filename) >  getMaximumFileUploadSize() );
}

/**
 * Get the original size of a zip archive to prevent Zip Bombing
 * see comment here : http://php.net/manual/en/function.zip-entry-filesize.php
 * @param string $filename
 * @return int
 */
function get_zip_originalsize($filename) {

    if ( function_exists ('zip_entry_filesize') ){
        $size = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4961,6 +4961,74 @@
     return false;
 }
 
+
+/**
+* Create a directory in tmp dir using a random string
+*
+* @param  string $dir      the temp directory (if empty will use the one from configuration)
+* @param  string $prefix   wanted prefix for the directory
+* @param  int    $mode     wanted  file mode for this directory
+* @return string           the path of the created directory
+*/
+function createRandomTempDir($dir=null, $prefix = '', $mode = 0700)
+{
+
+    $sDir = (empty($dir)) ? Yii::app()->getConfig('tempdir') : get_absolute_path ($dir);
+
+    if (substr($sDir, -1) != DIRECTORY_SEPARATOR) {
+        $sDir .= DIRECTORY_SEPARATOR;
+    }
+
+    do {
+        $sRandomString = getRandomString();
+        $path = $sDir.$prefix.$sRandomString;
+    }
+    while (!mkdir($path, $mode));
+
+    return $path;
+}
+
+/**
+ * Generate a random string, using openssl if available, else using md5
+ * @param  int    $length wanted lenght of the random string (only for openssl mode)
+ * @return string
+ */
+function getRandomString($length=32){
+
+    if ( function_exists('openssl_random_pseudo_bytes') ) {
+        $token = "";
+        $codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
+        $codeAlphabet.= "abcdefghijklmnopqrstuvwxyz";
+        $codeAlphabet.= "0123456789";
+        for($i=0;$i<$length;$i++){
+            $token .= $codeAlphabet[crypto_rand_secure(0,strlen($codeAlphabet))];
+        }
+    }else{
+        $token = md5(uniqid(rand(), true));
+    }
+    return $token;
+}
+
+/**
+ * Get a random number between two values using openssl_random_pseudo_bytes
+ * @param  int    $min
+ * @param  int    $max
+ * @return string
+ */
+function crypto_rand_secure($min, $max) {
+        $range = $max - $min;
+        if ($range < 0) return $min; // not so random...
+        $log = log($range, 2);
+        $bytes = (int) ($log / 8) + 1; // length in bytes
+        $bits = (int) $log + 1; // length in bits
+        $filter = (int) (1 << $bits) - 1; // set all lower bits to 1
+        do {
+            $rnd = hexdec(bin2hex(openssl_random_pseudo_bytes($bytes)));
+            $rnd = $rnd & $filter; // discard irrelevant bits
+        } while ($rnd >= $range);
+        return $min + $rnd;
+}
+
 /**
  * Test if a given zip file is Zip Bomb
  * see comment here : http://php.net/manual/en/function.zip-entry-filesize.php
```
