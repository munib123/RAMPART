# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4292_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4292_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php
$timeNow = time();
?>
<script src="<?= base_url('assets/ckeditor/ckeditor.js') ?>"></script>
<link rel="stylesheet" href="<?= base_url('assets/bootstrap-select-1.12.1/bootstrap-select.min.css') ?>">
<div class="row">
    <div class="col-md-6 col-md-offset-3">
        <?php
        if ($this->session->flashdata('result_publish')) {
            ?> 
            <div class="alert alert-success"><?= $this->session->flashdata('result_publish') ?></div> 
            <?php
        }
        ?>
        <div class="content">
            <form class="form-box" action="" method="POST" enctype="multipart/form-data">
                <input type="hidden" value="<?= isset($_POST['folder']) ? $_POST['folder'] : $timeNow ?>" name="folder">
                <div class="form-group available-translations">
                    <b>Languages</b>
                    <?php foreach ($languages as $language) { ?>
                        <button type="button" data-locale-change="<?= $language->abbr ?>" class="btn btn-default locale-change text-uppercase <?= $language->abbr == MY_DEFAULT_LANGUAGE_ABBR ? 'active' : '' ?>">
                            <img src="<?= base_url('attachments/lang_flags/' . $language->flag) ?>" alt="">
                            <?= $language->abbr ?>
                        </button>
                    <?php } ?>
                </div>
                <?php
                $i = 0;
                foreach ($languages as $language) {
                    ?>
                    <div class="locale-container locale-container-<?= $language->abbr ?>" <?= $language->abbr == MY_DEFAULT_LANGUAGE_ABBR ? 'style="display:block;"' : '' ?>>
                        <input type="hidden" name="translations[]" value="<?= $language->abbr ?>">
                        <div class="form-group">
                            <img src="<?= base_url('attachments/lang_flags/' . $language->flag) ?>" alt="<?= $language->name ?>" class="language">
                            <input type="text" name="title[]" placeholder="<?= lang('vendor_product_name') ?>" value="<?= $trans_load != null && isset($trans_load[$language->abbr]['title']) ? $trans_load[$language->abbr]['title'] : '' ?>" class="form-control">
                        </div> 
                        <label><?= lang('vendor_product_description') ?> <img src="<?= base_url('attachments/lang_flags/' . $language->flag) ?>" alt="<?= $language->name ?>"></label>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
         ?>
         <div class="content">
             <form class="form-box" action="" method="POST" enctype="multipart/form-data">
-                <input type="hidden" value="<?= isset($_POST['folder']) ? $_POST['folder'] : $timeNow ?>" name="folder">
+                <input type="hidden" value="<?= isset($_POST['folder']) ? htmlspecialchars($_POST['folder']) : $timeNow ?>" name="folder">
                 <div class="form-group available-translations">
                     <b>Languages</b>
                     <?php foreach ($languages as $language) { ?>
@@ -58,7 +58,7 @@
                 <div class="form-group bordered-group">
                     <?php
                     if (isset($_POST['image']) && $_POST['image'] != null) {
-                        $image = 'attachments/shop_images/' . $_POST['image'];
+                        $image = 'attachments/shop_images/' . htmlspecialchars($_POST['image']);
                         if (!file_exists($image)) {
                             $image = 'attachments/no-image.png';
                         }
@@ -67,9 +67,9 @@
                         <div>
                             <img src="<?= base_url($image) ?>" class="img-responsive img-thumbnail" style="max-width:300px; margin-bottom: 5px;">
                         </div>
-                        <input type="hidden" name="old_image" value="<?= $_POST['image'] ?>">
+                        <input type="hidden" name="old_image" value="<?= htmlspecialchars($_POST['image']) ?>">
                         <?php if (isset($_GET['to_lang'])) { ?>
-                            <input type="hidden" name="image" value="<?= $_POST['image'] ?>">
+                            <input type="hidden" name="image" value="<?= htmlspecialchars($_POST['image']) ?>">
                             <?php
                         }
                     }
@@ -110,10 +110,10 @@
                     </div>
                 <?php } ?>
                 <div class="form-group">
-                    <input type="text" placeholder="<?= lang('vendor_quantity') ?>" name="quantity" value="<?= @$_POST['quantity'] ?>" class="form-control">
+                    <input type="text" placeholder="<?= lang('vendor_quantity') ?>" name="quantity" value="<?= isset($_POST['quantity']) ? htmlspecialchars($_POST['quantity']) : '' ?>" class="form-control">
                 </div>
                 <div class="form-group">
-                    <input type="text" placeholder="<?= lang('vendor_position') ?>" name="position" value="<?= @$_POST['position'] ?>" class="form-control">
+                    <input type="text" placeholder="<?= lang('vendor_position') ?>" name="position" value="<?= isset($_POST['quantity']) ? htmlspecialchars($_POST['position']) : '' ?>" class="form-control">
                 </div>
                 <button type="submit" name="setProduct" class="btn btn-green"><?= lang('vendor_submit_product') ?></button>
             </form> 
@@ -130,7 +130,7 @@
             </div>
             <div class="modal-body">
                 <form id="uploadImagesForm">
-                    <input type="hidden" value="<?= isset($_POST['folder']) ? $_POST['folder'] : $timeNow ?>" name="folder">
+                    <input type="hidden" value="<?= isset($_POST['folder']) ? htmlspecialchars($_POST['folder']) : $timeNow ?>" name="folder">
                     <label for="others"><?= lang('vendor_select_images') ?></label>
                     <input type="file" name="others[]" id="others" multiple />
                 </form>
```
