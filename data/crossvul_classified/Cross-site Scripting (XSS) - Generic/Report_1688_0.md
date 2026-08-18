# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 1688_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1688_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 7-47 of the vulnerable file.

    data-sort-handler="<?= $this->getEventHandler('onSortAttachments') ?>"
    data-unique-id="<?= $this->getId() ?>"
    <?php if ($useCaption): ?>data-config-handler="<?= $this->getEventHandler('onLoadAttachmentConfig') ?>"<?php endif ?>
    <?php if ($acceptedFileTypes): ?>data-file-types="<?= $acceptedFileTypes ?>"<?php endif ?>
>

    <!-- Upload Button -->
    <button type="button" class="btn btn-sm btn-primary oc-icon-upload upload-button">
        <?= e(trans('backend::lang.fileupload.upload_file')) ?>
    </button>

    <!-- Existing files -->
    <div class="upload-files-container">
        <?php foreach ($fileList as $file): ?>
            <div class="upload-object is-success" data-id="<?= $file->id ?>" data-path="<?= $file->pathUrl ?>">
                <div class="icon-container">
                    <i class="icon-file"></i>
                </div>
                <div class="info">
                    <h4 class="filename">
                        <span data-dz-name><?= $file->title ?: $file->file_name ?></span>
                        <a
                            href="javascript:;"
                            class="upload-remove-button"
                            data-request="<?= $this->getEventHandler('onRemoveAttachment') ?>"
                            data-request-confirm="<?= e(trans('backend::lang.fileupload.remove_confirm')) ?>"
                            data-request-data="file_id: <?= $file->id ?>"
                            ><i class="icon-times"></i></a>
                    </h4>
                    <p class="size"><?= e($file->sizeToString()) ?></p>
                </div>
                <div class="meta">
                    <a href="javascript:;" class="drag-handle"><i class="icon-bars"></i></a>
                </div>
            </div>
        <?php endforeach ?>
    </div>
</div>

<!-- Template for new files -->
<script type="text/template" id="<?= $this->getId('template') ?>">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,7 @@
                 </div>
                 <div class="info">
                     <h4 class="filename">
-                        <span data-dz-name><?= $file->title ?: $file->file_name ?></span>
+                        <span data-dz-name><?= e($file->title ?: $file->file_name) ?></span>
                         <a
                             href="javascript:;"
                             class="upload-remove-button"
```
