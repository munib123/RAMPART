# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 1688_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1688_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 11-51 of the vulnerable file.

    <?php if ($acceptedFileTypes): ?>data-file-types="<?= $acceptedFileTypes ?>"<?php endif ?>
>

    <!-- Add New Image -->
    <a
        href="javascript:;"
        style="<?= $cssBlockDimensions ?>"
        class="upload-button">
        <span class="upload-button-icon oc-<?= $emptyIcon ?>"></span>
    </a>

    <!-- Existing file -->
    <div class="upload-files-container">
        <?php if ($singleFile): ?>
            <div class="upload-object is-success" data-id="<?= $singleFile->id ?>" data-path="<?= $singleFile->pathUrl ?>">
                <div class="icon-container image">
                    <img src="<?= $singleFile->thumbUrl ?>" />
                </div>
                <div class="info">
                    <h4 class="filename">
                        <span data-dz-name><?= $singleFile->title ?: $singleFile->file_name ?></span>
                        <a
                            href="javascript:;"
                            class="upload-remove-button"
                            data-request="<?= $this->getEventHandler('onRemoveAttachment') ?>"
                            data-request-confirm="<?= e(trans('backend::lang.fileupload.remove_confirm')) ?>"
                            data-request-data="file_id: <?= $singleFile->id ?>"
                            ><i class="icon-times"></i></a>
                    </h4>
                    <p class="size"><?= e($singleFile->sizeToString()) ?></p>
                </div>
                <div class="meta"></div>
            </div>
        <?php endif ?>
    </div>

</div>

<!-- Template for new file -->
<script type="text/template" id="<?= $this->getId('template') ?>">
    <div class="upload-object dz-preview dz-file-preview">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,7 @@
                 </div>
                 <div class="info">
                     <h4 class="filename">
-                        <span data-dz-name><?= $singleFile->title ?: $singleFile->file_name ?></span>
+                        <span data-dz-name><?= e($singleFile->title ?: $singleFile->file_name) ?></span>
                         <a
                             href="javascript:;"
                             class="upload-remove-button"
```
