# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 1301_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1301_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 5-45 of the vulnerable file.

    $load_lang_code = $_COOKIE['sy_lang'];
} else {
    $load_lang_code = "en";
}

// including lang files
switch ($load_lang_code) {
    case "en":
        require(__DIR__ . '/lang/en.php');
        break;
    case "pl":
        require(__DIR__ . '/lang/pl.php');
        break;
}

if(isset($_POST["newpath"]) or isset($_POST["extension"]) or isset($_GET["file_style"])){
    session_start();
}

if(isset($_SESSION['username'])){
    
    if(isset($_POST["newpath"])){
        $newpath = filter_input(INPUT_POST, 'newpath', FILTER_SANITIZE_STRING);
        $root = $_SERVER['DOCUMENT_ROOT'];
        $data = '
    $useruploadfolder = "'.$newpath.'";
    $useruploadpath = $usersiteroot."$useruploadfolder/";
    $foldershistory[] = "'.$newpath.'";
        '.PHP_EOL;
        $fp = fopen(__DIR__ . '/pluginconfig.php', 'a');
        fwrite($fp, $data);
    }
    
    if(isset($_POST["extension"])){
        $extension_setting = filter_input(INPUT_POST, 'extension', FILTER_SANITIZE_STRING);
        if($extension_setting == "no" or $extension_setting == "yes"){
            setcookie(
                "file_extens",
                $extension_setting,
                time() + (10 * 365 * 24 * 60 * 60)
            );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,19 +22,21 @@
 }
 
 if(isset($_SESSION['username'])){
-    
+
     if(isset($_POST["newpath"])){
-        $newpath = filter_input(INPUT_POST, 'newpath', FILTER_SANITIZE_STRING);
+        $options = array("flags" => FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH | FILTER_FLAG_STRIP_BACKTICK);
+        $newpath = filter_input(INPUT_POST, 'newpath', FILTER_SANITIZE_STRING, $options);
+        $newpath = addslashes($newpath);
         $root = $_SERVER['DOCUMENT_ROOT'];
         $data = '
-    $useruploadfolder = "'.$newpath.'";
+    $useruploadfolder = \''.$newpath.'\';
     $useruploadpath = $usersiteroot."$useruploadfolder/";
-    $foldershistory[] = "'.$newpath.'";
+    $foldershistory[] = \''.$newpath.'\';
         '.PHP_EOL;
         $fp = fopen(__DIR__ . '/pluginconfig.php', 'a');
         fwrite($fp, $data);
     }
-    
+
     if(isset($_POST["extension"])){
         $extension_setting = filter_input(INPUT_POST, 'extension', FILTER_SANITIZE_STRING);
         if($extension_setting == "no" or $extension_setting == "yes"){
@@ -51,7 +53,7 @@
                 </script>
             ';
         }
-    } 
+    }
     if(isset($_GET["file_style"])){
         $file_style = filter_input(INPUT_GET, 'file_style', FILTER_SANITIZE_STRING);
         if($file_style == "block" or $file_style == "list"){
@@ -69,8 +71,8 @@
                 </script>
             ';
         }
-    } 
-    
+    }
+
 }
 
 // Version of the plugin
@@ -84,7 +86,7 @@
 $password = "";
 
 // ststem icons
-$sy_icons = array( 
+$sy_icons = array(
     "cd-ico-browser.ico",
     "cd-icon-block.png",
     "cd-icon-browser.png",
```
