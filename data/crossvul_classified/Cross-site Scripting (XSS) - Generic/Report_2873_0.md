# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2873_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2873_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 122-162 of the vulnerable file.


}

if (!isset($_SESSION['phpmyfaq_csrf_token']) || $_SESSION['phpmyfaq_csrf_token'] !== $currentToken) {
    $auth = false;
}

if (!is_null($currentAction) && $auth && !$user->perm->checkRight($user->getUserId(), 'addattachment')) {
    echo $PMF_LANG['err_NotAuth'];
}

if (!is_null($currentSave) && $currentSave == true && $auth &&
    $user->perm->checkRight($user->getUserId(), 'addattachment')) {
    $recordId = filter_input(INPUT_POST, 'record_id',   FILTER_VALIDATE_INT);
    $recordLang = filter_input(INPUT_POST, 'record_lang', FILTER_SANITIZE_STRING);
    ?>
<p>
    <strong><?php echo $PMF_LANG['ad_att_addto'].' '.$PMF_LANG['ad_att_addto_2'] ?></strong>
</p>
<?php
    if (is_uploaded_file($_FILES['userfile']['tmp_name']) && !($_FILES['userfile']['size'] > $faqConfig->get('records.maxAttachmentSize'))) {
        $att = PMF_Attachment_Factory::create();
        $att->setRecordId($recordId);
        $att->setRecordLang($recordLang);

        /*
         * To add user defined key
         * $att->setKey($somekey, false);
         */
        try {
            $uploaded = $att->save($_FILES['userfile']['tmp_name'], $_FILES['userfile']['name']);

            if ($uploaded) {
                echo '<p>'.$PMF_LANG['ad_att_suc'].'</p>';
            } else {
                throw new Exception();
            }
        } catch (Exception $e) {
            $att->delete();
            echo '<p>'.$PMF_LANG['ad_att_fail'].'</p>';
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -139,7 +139,11 @@
     <strong><?php echo $PMF_LANG['ad_att_addto'].' '.$PMF_LANG['ad_att_addto_2'] ?></strong>
 </p>
 <?php
-    if (is_uploaded_file($_FILES['userfile']['tmp_name']) && !($_FILES['userfile']['size'] > $faqConfig->get('records.maxAttachmentSize'))) {
+    if (
+        is_uploaded_file($_FILES['userfile']['tmp_name']) &&
+        !($_FILES['userfile']['size'] > $faqConfig->get('records.maxAttachmentSize')) &&
+        $_FILES['userfile']['type'] !== "text/html"
+    ) {
         $att = PMF_Attachment_Factory::create();
         $att->setRecordId($recordId);
         $att->setRecordLang($recordLang);
```
