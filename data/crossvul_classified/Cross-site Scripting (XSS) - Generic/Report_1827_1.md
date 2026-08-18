# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1827_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1827_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 74-114 of the vulnerable file.

// render thumbnail of an image attachment
else if ($_GET['_thumb']) {
    $pid = rcube_utils::get_input_value('_part', rcube_utils::INPUT_GET);
    if ($part = $MESSAGE->mime_parts[$pid]) {
        $thumbnail_size = $RCMAIL->config->get('image_thumbnail_size', 240);
        $temp_dir       = $RCMAIL->config->get('temp_dir');
        $mimetype       = $part->mimetype;
        $file_ident     = $MESSAGE->headers->messageID . ':' . $part->mime_id . ':' . $part->size . ':' . $part->mimetype;
        $cache_basename = $temp_dir . '/' . md5($file_ident . ':' . $RCMAIL->user->ID . ':' . $thumbnail_size);
        $cache_file     = $cache_basename . '.thumb';

        // render thumbnail image if not done yet
        if (!is_file($cache_file)) {
            if ($fp = fopen(($orig_name = $cache_basename . '.tmp'), 'w')) {
                $MESSAGE->get_part_body($part->mime_id, false, 0, $fp);
                fclose($fp);

                $image = new rcube_image($orig_name);
                if ($imgtype = $image->resize($thumbnail_size, $cache_file, true)) {
                    $mimetype = 'image/' . $imgtype;
                    unlink($orig_name);
                }
                else {
                    rename($orig_name, $cache_file);
                }
            }
        }

        if (is_file($cache_file)) {
            header('Content-Type: ' . $mimetype);
            readfile($cache_file);
        }
    }

    exit;
}
else if (strlen($part_id)) {
    if ($part = $MESSAGE->mime_parts[$part_id]) {
        $mimetype = rcmail_fix_mimetype($part->mimetype);

        // allow post-processing of the message body
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,6 +93,11 @@
                     $mimetype = 'image/' . $imgtype;
                     unlink($orig_name);
                 }
+                else if (stripos($mimetype, 'image/svg') === 0) {
+                    $content = rcmail_svg_filter(file_get_contents($orig_name));
+                    file_put_contents($cache_file, $content);
+                    unlink($orig_name);
+                }
                 else {
                     rename($orig_name, $cache_file);
                 }
@@ -329,7 +334,7 @@
                 }
 
                 // convert image to jpeg and send it to the browser
-                if ($saved) {
+                if ($sent = $saved) {
                     $image = new rcube_image($file_path);
                     if ($image->convert(rcube_image::TYPE_JPG, $file_path)) {
                         header("Content-Length: " . filesize($file_path));
@@ -338,32 +343,8 @@
                     unlink($file_path);
                 }
             }
-            // do content filtering to avoid XSS through fake images
-            else if (!empty($_REQUEST['_embed']) && $browser->ie && $browser->ver <= 8) {
-                if ($body) {
-                    echo preg_match('/<(script|iframe|object)/i', $body) ? '' : $body;
-                    $sent = true;
-                }
-                else if ($part->size) {
-                    $stdout = fopen('php://output', 'w');
-                    stream_filter_register('rcube_content', 'rcube_content_filter') or die('Failed to register content filter');
-                    stream_filter_append($stdout, 'rcube_content');
-                    $sent = $MESSAGE->get_part_body($part->mime_id, true, 0, $stdout);
-                }
-            }
-            // send part as-it-is
             else {
-                if ($body && empty($plugin['download'])) {
-                    header("Content-Length: " . strlen($body));
-                    echo $body;
-                    $sent = true;
-                }
-                else if ($part->size) {
-                    // Don't be tempted to set Content-Length to $part->d_parameters['size'] (#1490482)
-                    // RFC2183 says "The size parameter indicates an approximate size"
-
-                    $sent = $MESSAGE->get_part_body($part->mime_id, false, 0, -1);
-                }
+                $sent = rcmail_message_part_output($body, $part, $mimetype, $plugin['download']);
             }
 
             // check connection status
@@ -475,3 +456,71 @@
 
     return html::iframe($attrib);
 }
+
+/**
+ * Output attachment body with content filtering
+ */
+function rcmail_message_part_output($body, $part, $mimetype, $download)
+{
+    global $MESSAGE, $RCMAIL;
+
+    if (!$part->size && !$body) {
+        return false;
+    }
+
+    $browser = $RCMAIL->output->browser;
+    $secure  = stripos($mimetype, 'image/') === false || $download;
+
+    // Remove <script> in SVG images
+    if (!$secure && stripos($mimetype, 'image/svg') === 0) {
+        if (!$body) {
+            $body = $MESSAGE->get_part_body($part->mime_id, false);
+            if (empty($body)) {
+                return false;
+            }
+        }
+
+        echo rcmail_svg_filter($body);
+        return true;
+    }
+
+    // Remove dangerous content in images for older IE (to be removed)
+    if (!$secure && $browser->ie && $browser->ver <= 8) {
+        if ($body) {
+            echo preg_match('/<(script|iframe|object)/i', $body) ? '' : $body;
+            return true;
+        }
+        else {
+            $stdout = fopen('php://output', 'w');
+            stream_filter_register('rcube_content', 'rcube_content_filter') or die('Failed to register content filter');
+            stream_filter_append($stdout, 'rcube_content');
+            return $MESSAGE->get_part_body($part->mime_id, true, 0, $stdout);
+        }
+    }
+
+    if ($body && !$download) {
+        header("Content-Length: " . strlen($body));
+        echo $body;
+        return true;
+    }
+
+    // Don't be tempted to set Content-Length to $part->d_parameters['size'] (#1490482)
+    // RFC2183 says "The size parameter indicates an approximate size"
+
+    return $MESSAGE->get_part_body($part->mime_id, false, 0, -1);
+}
+
+/**
+ * Remove <script> in SVG images
+ */
+function rcmail_svg_filter($body)
+{
+    $dom = new DOMDocument;
+    $dom->loadXML($body);
+
+    foreach ($dom->getElementsByTagName('script') as $node) {
+        $node->parentNode->removeChild($node);
+    }
+
+    return $dom->saveXML() ?: '';
+}
```
