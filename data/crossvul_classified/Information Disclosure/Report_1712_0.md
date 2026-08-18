# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1712_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1712_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 45-85 of the vulnerable file.

        'shadow_offset_x' => -1,
        'shadow_offset_y' => 1
    );

    // Overwrite defaults with custom config values
    if( is_array($config) ) {
        foreach( $config as $key => $value ) $captcha_config[$key] = $value;
    }

    // Restrict certain values
    if( $captcha_config['min_length'] < 1 ) $captcha_config['min_length'] = 1;
    if( $captcha_config['angle_min'] < 0 ) $captcha_config['angle_min'] = 0;
    if( $captcha_config['angle_max'] > 10 ) $captcha_config['angle_max'] = 10;
    if( $captcha_config['angle_max'] < $captcha_config['angle_min'] ) $captcha_config['angle_max'] = $captcha_config['angle_min'];
    if( $captcha_config['min_font_size'] < 10 ) $captcha_config['min_font_size'] = 10;
    if( $captcha_config['max_font_size'] < $captcha_config['min_font_size'] ) $captcha_config['max_font_size'] = $captcha_config['min_font_size'];

    // Generate CAPTCHA code if not set by user
    if( empty($captcha_config['code']) ) {
        $captcha_config['code'] = '';
        $length = rand($captcha_config['min_length'], $captcha_config['max_length']);
        while( strlen($captcha_config['code']) < $length ) {
            $captcha_config['code'] .= substr($captcha_config['characters'], rand() % (strlen($captcha_config['characters'])), 1);
        }
    }

    // Generate HTML for image src
    if ( strpos($_SERVER['SCRIPT_FILENAME'], $_SERVER['DOCUMENT_ROOT']) ) {
        $image_src = substr(__FILE__, strlen( realpath($_SERVER['DOCUMENT_ROOT']) )) . '?_CAPTCHA&amp;t=' . urlencode(microtime());
        $image_src = '/' . ltrim(preg_replace('/\\\\/', '/', $image_src), '/');
    } else {
        $_SERVER['WEB_ROOT'] = str_replace($_SERVER['SCRIPT_NAME'], '', $_SERVER['SCRIPT_FILENAME']);
        $image_src = substr(__FILE__, strlen( realpath($_SERVER['WEB_ROOT']) )) . '?_CAPTCHA&amp;t=' . urlencode(microtime());
        $image_src = '/' . ltrim(preg_replace('/\\\\/', '/', $image_src), '/');
    }

    $_SESSION['_CAPTCHA']['config'] = serialize($captcha_config);

    return array(
        'code' => $captcha_config['code'],
        'image_src' => $image_src
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,9 +62,9 @@
     // Generate CAPTCHA code if not set by user
     if( empty($captcha_config['code']) ) {
         $captcha_config['code'] = '';
-        $length = rand($captcha_config['min_length'], $captcha_config['max_length']);
+        $length = mt_rand($captcha_config['min_length'], $captcha_config['max_length']);
         while( strlen($captcha_config['code']) < $length ) {
-            $captcha_config['code'] .= substr($captcha_config['characters'], rand() % (strlen($captcha_config['characters'])), 1);
+            $captcha_config['code'] .= substr($captcha_config['characters'], mt_rand() % (strlen($captcha_config['characters'])), 1);
         }
     }
 
@@ -119,7 +119,7 @@
     unset($_SESSION['_CAPTCHA']);
 
     // Pick random background, get info, and start captcha
-    $background = $captcha_config['backgrounds'][rand(0, count($captcha_config['backgrounds']) -1)];
+    $background = $captcha_config['backgrounds'][mt_rand(0, count($captcha_config['backgrounds']) -1)];
     list($bg_width, $bg_height, $bg_type, $bg_attr) = getimagesize($background);
 
     $captcha = imagecreatefrompng($background);
@@ -128,16 +128,16 @@
     $color = imagecolorallocate($captcha, $color['r'], $color['g'], $color['b']);
 
     // Determine text angle
-    $angle = rand( $captcha_config['angle_min'], $captcha_config['angle_max'] ) * (rand(0, 1) == 1 ? -1 : 1);
+    $angle = mt_rand( $captcha_config['angle_min'], $captcha_config['angle_max'] ) * (mt_rand(0, 1) == 1 ? -1 : 1);
 
     // Select font randomly
-    $font = $captcha_config['fonts'][rand(0, count($captcha_config['fonts']) - 1)];
+    $font = $captcha_config['fonts'][mt_rand(0, count($captcha_config['fonts']) - 1)];
 
     // Verify font file exists
     if( !file_exists($font) ) throw new Exception('Font file not found: ' . $font);
 
     //Set the font size.
-    $font_size = rand($captcha_config['min_font_size'], $captcha_config['max_font_size']);
+    $font_size = mt_rand($captcha_config['min_font_size'], $captcha_config['max_font_size']);
     $text_box_size = imagettfbbox($font_size, $angle, $font, $captcha_config['code']);
 
     // Determine text position
@@ -145,10 +145,15 @@
     $box_height = abs($text_box_size[5] - $text_box_size[1]);
     $text_pos_x_min = 0;
     $text_pos_x_max = ($bg_width) - ($box_width);
-    $text_pos_x = rand($text_pos_x_min, $text_pos_x_max);
+    $text_pos_x = mt_rand($text_pos_x_min, $text_pos_x_max);
     $text_pos_y_min = $box_height;
     $text_pos_y_max = ($bg_height) - ($box_height / 2);
-    $text_pos_y = rand($text_pos_y_min, $text_pos_y_max);
+    if ($text_pos_y_min > $text_pos_y_max) {
+        $temp_text_pos_y = $text_pos_y_min;
+        $text_pos_y_min = $text_pos_y_max;
+        $text_pos_y_max = $temp_text_pos_y;
+    }
+    $text_pos_y = mt_rand($text_pos_y_min, $text_pos_y_max);
 
     // Draw shadow
     if( $captcha_config['shadow'] ){
```
