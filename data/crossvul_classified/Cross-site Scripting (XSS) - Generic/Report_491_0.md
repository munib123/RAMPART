# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 491_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `491_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 2-44 of the vulnerable file.

<div class='side-body <?php echo getSideBodyClass(false); ?>'>
    <div class="row welcome survey-action">
        <div class="col-sm-12 content-right">
            <div class="jumbotron message-box">
                <h2><?php eT("Import survey resources"); ?></h2>
                <p class="lead text-success">
                    <?php eT("Success");?>
                </p>
                <p>
                    <?php eT("Resources Import Summary"); ?>
                </p>
                <p>
                    <?php eT("Total Imported files"); ?>: <?php echo count($aImportedFilesInfo); ?><br />
                </p>
                <p>
                    <strong><?php eT("Imported Files List") ?>:</strong>
                </p>
                <p>
                    <ul>
                        <?php
                        foreach ($aImportedFilesInfo as $entry)
                        {
                            echo CHtml::tag('li', array(), gT("File") . ': ' . $entry["filename"]);
                        }
                        ?>
                    </ul>
                </p>
                <p>
                    <input class="btn btn-default btn-lg" type='submit' value='<?php eT("Back"); ?>' onclick="window.open('<?php echo $this->createUrl('admin/survey/sa/editlocalsettings/surveyid/' . $surveyid); ?>', '_top')" />
                </p>
            </div>
        </div>
    </div>
</div>
<?php elseif(count($aErrorFilesInfo) &&count($aImportedFilesInfo)): ?>
    <div class='side-body <?php echo getSideBodyClass(false); ?>'>
        <div class="row welcome survey-action">
            <div class="col-sm-12 content-right">
                <div class="jumbotron message-box message-box-warning">
                    <h2><?php eT("Import survey resources"); ?></h2>
                    <p class="lead text-warning">
                        <?php eT("Partial");?>
                    </p>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,9 +19,8 @@
                 <p>
                     <ul>
                         <?php
-                        foreach ($aImportedFilesInfo as $entry)
-                        {
-                            echo CHtml::tag('li', array(), gT("File") . ': ' . $entry["filename"]);
+                        foreach ($aImportedFilesInfo as $entry) {
+                            echo CHtml::tag('li', array(), sprintf(gT("File: %s"),CHtml::encode($entry["filename"])));
                         }
                         ?>
                     </ul>
@@ -55,9 +54,8 @@
                     <p>
                         <ul>
                             <?php
-                            foreach ($aImportedFilesInfo as $entry)
-                            {
-                                echo CHtml::tag('li', array(), gT("File") . ': ' . $entry["filename"]);
+                            foreach ($aImportedFilesInfo as $entry) {
+                                echo CHtml::tag('li', array(), sprintf(gT("File: %s"),CHtml::encode($entry["filename"])));
                             }
                             ?>
                         </ul>
@@ -67,9 +65,8 @@
                     </p>
                     <p>
                         <?php
-                            foreach ($aErrorFilesInfo as $entry)
-                            {
-                                echo CHtml::tag('li', array(), gT("File") . ': ' . $entry['filename'] . " (" . $entry['status'] . ")");
+                            foreach ($aErrorFilesInfo as $entry) {
+                                echo CHtml::tag('li', array(), sprintf(gT("File: %s (%s)"),CHtml::encode($entry["filename"]),$entry['status']));
                             }
                         ?>
                         </ul>
@@ -102,9 +99,8 @@
                     </p>
                     <p>
                         <?php
-                            foreach ($aErrorFilesInfo as $entry)
-                            {
-                                echo CHtml::tag('li', array(), gT("File") . ': ' . $entry['filename'] . " (" . $entry['status'] . ")");
+                            foreach ($aErrorFilesInfo as $entry) {
+                                echo CHtml::tag('li', array(), sprintf(gT("File: %s (%s)"),CHtml::encode($entry["filename"]),$entry['status']));
                             }
                         ?>
                         </ul>
```
