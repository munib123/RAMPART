# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1680_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1680_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 63-95 of the vulnerable file.

            $data = base64_decode($data, true);
    }
}

// let plugins do fancy things with contact photos
$plugin = $RCMAIL->plugins->exec_hook('contact_photo',
    array('record' => $record, 'email' => $email, 'data' => $data));

// redirect to url provided by a plugin
if ($plugin['url']) {
    $RCMAIL->output->redirect($plugin['url']);
}

$data = $plugin['data'];

// detect if photo data is an URL
if (strlen($data) < 1024 && filter_var($data, FILTER_VALIDATE_URL)) {
    $RCMAIL->output->redirect($data);
}

// deliver alt image
if (!$data && ($alt_img = rcube_utils::get_input_value('_alt', rcube_utils::INPUT_GPC)) && is_file($alt_img)) {
    $data = file_get_contents($alt_img);
}

// cache for one day if requested by email
if (!$cid && $email) {
    $RCMAIL->output->future_expire_header(86400);
}

header('Content-Type: ' . rcube_mime::image_content_type($data));
echo $data ? $data : file_get_contents('program/resources/blank.gif');
exit;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,11 +80,6 @@
     $RCMAIL->output->redirect($data);
 }
 
-// deliver alt image
-if (!$data && ($alt_img = rcube_utils::get_input_value('_alt', rcube_utils::INPUT_GPC)) && is_file($alt_img)) {
-    $data = file_get_contents($alt_img);
-}
-
 // cache for one day if requested by email
 if (!$cid && $email) {
     $RCMAIL->output->future_expire_header(86400);
```
