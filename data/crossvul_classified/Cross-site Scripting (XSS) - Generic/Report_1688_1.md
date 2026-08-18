# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 1688_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1688_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 6-46 of the vulnerable file.

    data-error-template="#<?= $this->getId('errorTemplate') ?>"
    data-unique-id="<?= $this->getId() ?>"
    <?php if ($useCaption): ?>data-config-handler="<?= $this->getEventHandler('onLoadAttachmentConfig') ?>"<?php endif ?>
    <?php if ($acceptedFileTypes): ?>data-file-types="<?= $acceptedFileTypes ?>"<?php endif ?>
>

    <!-- Upload Button -->
    <button type="button" class="btn btn-default upload-button">
        <i class="icon-upload"></i>
    </button>

    <!-- Existing file -->
    <div class="upload-files-container">
        <?php if ($singleFile): ?>
            <div class="upload-object is-success" data-id="<?= $singleFile->id ?>" data-path="<?= $singleFile->pathUrl ?>">
                <div class="icon-container">
                    <i class="icon-file"></i>
                </div>
                <div class="info">
                    <h4 class="filename">
                        <span data-dz-name><?= $singleFile->title ?: $singleFile->file_name ?></span>
                    </h4>
                    <p class="size"><?= e($singleFile->sizeToString()) ?></p>
                </div>
                <div class="meta">
                    <a
                        href="javascript:;"
                        class="upload-remove-button"
                        data-request="<?= $this->getEventHandler('onRemoveAttachment') ?>"
                        data-request-confirm="<?= e(trans('backend::lang.fileupload.remove_confirm')) ?>"
                        data-request-data="file_id: <?= $singleFile->id ?>"
                        ><i class="icon-times"></i></a>
                </div>
            </div>
        <?php endif ?>
    </div>

    <!-- Empty message -->
    <div class="upload-empty-message">
        <span class="text-muted"><?= $prompt ?></span>
    </div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,7 +23,7 @@
                 </div>
                 <div class="info">
                     <h4 class="filename">
-                        <span data-dz-name><?= $singleFile->title ?: $singleFile->file_name ?></span>
+                        <span data-dz-name><?= e($singleFile->title ?: $singleFile->file_name) ?></span>
                     </h4>
                     <p class="size"><?= e($singleFile->sizeToString()) ?></p>
                 </div>
```
