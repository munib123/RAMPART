# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 491_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `491_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 35-75 of the vulnerable file.

                <?php echo $status ?>
            </p>

            <p>
                <strong><u><?php eT("Resources import summary") ?></u></strong><br />
                <?php echo gT("Files imported:") . " $okfiles" ?><br />
                <?php echo gT("Files skipped:") . " $errfiles" ?><br />
            </p>
            <p>
                <?php
                    if (count($aImportedFilesInfo) > 0)
                    {
                    ?>
                    <br /><strong><u><?php eT("Imported files:") ?></u></strong><br />
                    <ul style="max-height: 250px; overflow-y:scroll;" class="list-unstyled">
                        <?php
                            foreach ($aImportedFilesInfo as $entry)
                            {
                                if ($entry['is_folder']){
                                ?>
                                <li><?php echo gT("Folder:") . " " . htmlspecialchars($entry["filename"],ENT_QUOTES,'utf-8'); ?></li>
                                <?php
                                }
                                else
                                { ?>
                                <li><?php echo gT("File:") . " " . htmlspecialchars($entry["filename"],ENT_QUOTES,'utf-8'); ?></li>


                                <?php
                                }
                            }
                        }
                        if (count($aErrorFilesInfo) > 0)
                        {
                        ?>
                    </ul>
                    <br /><strong><u><?php eT("Skipped files:") ?></u></strong><br />
                    <ul style="max-height: 250px; overflow-y:scroll;" class="list-unstyled">
                        <?php
                            foreach ($aErrorFilesInfo as $entry)
                            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -52,12 +52,12 @@
                             {
                                 if ($entry['is_folder']){
                                 ?>
-                                <li><?php echo gT("Folder:") . " " . htmlspecialchars($entry["filename"],ENT_QUOTES,'utf-8'); ?></li>
+                                <li><?php printf(gT("Folder: %s"),CHtml::encode($entry["filename"])); ?></li>
                                 <?php
                                 }
                                 else
                                 { ?>
-                                <li><?php echo gT("File:") . " " . htmlspecialchars($entry["filename"],ENT_QUOTES,'utf-8'); ?></li>
+                                <li><?php printf(gT("File: %s"),CHtml::encode($entry["filename"])); ?></li>
 
 
                                 <?php
@@ -74,7 +74,7 @@
                             foreach ($aErrorFilesInfo as $entry)
                             {
                             ?>
-                            <li><?php echo gT("File:") . " " . $entry["filename"] ?></li>
+                            <li><?php printf(gT("File: %s"),CHtml::encode($entry["filename"])); ?></li>
                             <?php
                             }
                         }
```
