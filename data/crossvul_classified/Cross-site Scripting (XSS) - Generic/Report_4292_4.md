# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4292_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4292_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2-42 of the vulnerable file.

<h1><img src="<?= base_url('assets/imgs/shop-cart-add-icon.png') ?>" class="header-img" style="margin-top:-3px;"> Publish product</h1>
<hr>
<?php
$timeNow = time();
if (validation_errors()) {
    ?>
    <hr>
    <div class="alert alert-danger"><?= validation_errors() ?></div>
    <hr>
    <?php
}
if ($this->session->flashdata('result_publish')) {
    ?>
    <hr>
    <div class="alert alert-success"><?= $this->session->flashdata('result_publish') ?></div>
    <hr>
    <?php
}
?>
<form method="POST" action="" enctype="multipart/form-data">
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
                <label>Title (<?= $language->name ?><img src="<?= base_url('attachments/lang_flags/' . $language->flag) ?>" alt="">)</label>
                <input type="text" name="title[]" value="<?= $trans_load != null && isset($trans_load[$language->abbr]['title']) ? $trans_load[$language->abbr]['title'] : '' ?>" class="form-control">
            </div>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,7 +19,7 @@
 }
 ?>
 <form method="POST" action="" enctype="multipart/form-data">
-    <input type="hidden" value="<?= isset($_POST['folder']) ? $_POST['folder'] : $timeNow ?>" name="folder">
+    <input type="hidden" value="<?= isset($_POST['folder']) ? htmlspecialchars($_POST['folder']) : $timeNow ?>" name="folder">
     <div class="form-group available-translations">
         <b>Languages</b>
         <?php foreach ($languages as $language) { ?>
@@ -77,7 +77,7 @@
     <div class="form-group bordered-group">
         <?php
         if (isset($_POST['image']) && $_POST['image'] != null) {
-            $image = 'attachments/shop_images/' . $_POST['image'];
+            $image = 'attachments/shop_images/' . htmlspecialchars($_POST['image']);
             if (!file_exists($image)) {
                 $image = 'attachments/no-image.png';
             }
@@ -86,9 +86,9 @@
             <div>
                 <img src="<?= base_url($image) ?>" class="img-responsive img-thumbnail" style="max-width:300px; margin-bottom: 5px;">
             </div>
-            <input type="hidden" name="old_image" value="<?= $_POST['image'] ?>">
+            <input type="hidden" name="old_image" value="<?= htmlspecialchars($_POST['image']) ?>">
             <?php if (isset($_GET['to_lang'])) { ?>
-                <input type="hidden" name="image" value="<?= $_POST['image'] ?>">
+                <input type="hidden" name="image" value="<?= htmlspecialchars($_POST['image']) ?>">
                 <?php
             }
         }
@@ -120,7 +120,7 @@
     </div>
     <div class="form-group for-shop">
         <label>Quantity</label>
-        <input type="text" placeholder="number" name="quantity" value="<?= @$_POST['quantity'] ?>" class="form-control" id="quantity">
+        <input type="text" placeholder="number" name="quantity" value="<?= isset($_POST['quantity']) ? htmlspecialchars($_POST['quantity']) : '' ?>" class="form-control" id="quantity">
     </div>
     <?php if ($showBrands == 1) { ?>
         <div class="form-group for-shop">
@@ -134,7 +134,7 @@
     <?php } if ($virtualProducts == 1) { ?>
         <div class="form-group for-shop">
             <label>Virtual Products <a href="javascript:void(0);" data-toggle="modal" data-target="#virtualProductsHelp"><i class="fa fa-question-circle" aria-hidden="true"></i></a></label>
-            <textarea class="form-control" name="virtual_products"><?= @$_POST['virtual_products'] ?></textarea>
+            <textarea class="form-control" name="virtual_products"><?= isset($_POST['virtual_products']) ? htmlspecialchars($_POST['virtual_products']) : '' ?></textarea>
         </div>
     <?php } ?>
     <div class="form-group for-shop">
@@ -146,7 +146,7 @@
     </div>
     <div class="form-group for-shop">
         <label>Position</label>
-        <input type="text" placeholder="Position number" name="position" value="<?= @$_POST['position'] ?>" class="form-control">
+        <input type="text" placeholder="Position number" name="position" value="<?= isset($_POST['position']) ? htmlspecialchars($_POST['position']) : '' ?>" class="form-control">
     </div>
     <button type="submit" name="submit" class="btn btn-lg btn-default btn-publish">Publish</button>
     <?php if ($this->uri->segment(3) !== null) { ?>
@@ -163,7 +163,7 @@
             </div>
             <div class="modal-body">
                 <form id="uploadImagesForm">
-                    <input type="hidden" value="<?= isset($_POST['folder']) ? $_POST['folder'] : $timeNow ?>" name="folder">
+                    <input type="hidden" value="<?= isset($_POST['folder']) ? htmlspecialchars($_POST['folder']) : $timeNow ?>" name="folder">
                     <label for="others">Select images</label>
                     <input type="file" name="others[]" id="others" multiple />
                 </form>
```
