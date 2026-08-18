# CrossVul Fix Pair: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') in php
**Pair ID:** 4003_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-88
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4003_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') - When creating commands using interpolation into a string, developers may assume that only the arguments/options that they specify will be processed.

## Vulnerable Code
```php
Lines 141-181 of the vulnerable file.

                $valid_types = "bmp,eps,gif,jp2,jpg,png,svg,tif";

                if (in_array($type, explode(',', $valid_types))) { // Valid type?
                    if ($scale >= 1) {
                        $width  = $props['width'];
                        $height = $props['height'];
                    }
                    else {
                        $width  = intval($props['width']  * $scale);
                        $height = intval($props['height'] * $scale);
                    }

                    // use ImageMagick in command line
                    if ($convert) {
                        $p += array(
                            'type'    => $type,
                            'quality' => 75,
                            'size'    => $width . 'x' . $height,
                        );

                        $result = rcube::exec($convert . ' 2>&1 -flatten -auto-orient -colorspace sRGB -strip'
                            . ' -quality {quality} -resize {size} {intype}:{in} {type}:{out}', $p);
                    }
                    // use PHP's Imagick class
                    else {
                        try {
                            $image = new Imagick($this->image_file);

                            try {
                                // it throws exception on formats not supporting these features
                                $image->setImageBackgroundColor('white');
                                $image->setImageAlphaChannel(11);
                                $image->mergeImageLayers(Imagick::LAYERMETHOD_FLATTEN);
                            }
                            catch (Exception $e) {
                                // ignore errors
                            }

                            $image->setImageColorspace(Imagick::COLORSPACE_SRGB);
                            $image->setImageCompressionQuality(75);
                            $image->setImageFormat($type);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,7 +158,8 @@
                             'size'    => $width . 'x' . $height,
                         );
 
-                        $result = rcube::exec($convert . ' 2>&1 -flatten -auto-orient -colorspace sRGB -strip'
+                        $result = rcube::exec(escapeshellcmd($convert)
+                            . ' 2>&1 -flatten -auto-orient -colorspace sRGB -strip'
                             . ' -quality {quality} -resize {size} {intype}:{in} {type}:{out}', $p);
                     }
                     // use PHP's Imagick class
@@ -323,7 +324,8 @@
             $p['out']  = $filename;
             $p['type'] = self::$extensions[$type];
 
-            $result = rcube::exec($convert . ' 2>&1 -colorspace sRGB -strip -flatten -quality 75 {in} {type}:{out}', $p);
+            $result = rcube::exec(escapeshellcmd($convert)
+                . ' 2>&1 -colorspace sRGB -strip -flatten -quality 75 {in} {type}:{out}', $p);
 
             if ($result === '') {
                 chmod($filename, 0600);
@@ -419,7 +421,7 @@
         // use ImageMagick in command line
         if ($cmd = $rcube->config->get('im_identify_path')) {
             $args = array('in' => $this->image_file, 'format' => "%m %[fx:w] %[fx:h]");
-            $id   = rcube::exec($cmd. ' 2>/dev/null -format {format} {in}', $args);
+            $id   = rcube::exec(escapeshellcmd($cmd) . ' 2>/dev/null -format {format} {in}', $args);
 
             if ($id) {
                 return explode(' ', strtolower($id));
```
