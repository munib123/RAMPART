# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4292_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4292_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 66-106 of the vulnerable file.

                <?php } ?>
            </table>
        </div>
    <?php } else { ?>
        <div class="clearfix"></div><hr>
        <div class="alert alert-info">No languages found!</div>
    <?php } ?>
    <div class="alert alert-warning">
        <b>How to add language in 2 easy steps</b>
        <ul>
            <li>Add languages here (set Abbrevation, Name, and Image)</li>
            <li>Edit added language and set values</li>
        </ul>
    </div>

    <?php
    if (isset($_GET['editLang'])) {
        ?>
        <form method="POST" id="saveLang">
            <input type="hidden" name="goDaddyGo" value="">
            <div class="alert alert-info"><span class="glyphicon glyphicon-alert"></span> Now you edit language: <b><?= ucfirst($_GET['editLang']) ?></b></div>
            <?php
            $o = 1;
            $countValuesForEdit = 0;
            foreach ($arrPhpFiles as $phpFile => $langFinal) {
                if (!empty($langFinal)) {
                    foreach ($langFinal as $key => $val) {
                        ?>
                        <div class="divLangs">
                            <span><b><?= $o ?>.</b> <?= $val ?></span>
                            <input type="hidden" name="php_files[]" value="<?= $phpFile ?>">
                            <input type="hidden" name="php_keys[]" value="<?= $key ?>">
                            <input type="text" value="<?= $val ?>" class="form-control" name="php_values[]">
                        </div>
                        <?php
                        $o++;
                        $countValuesForEdit++;
                    }
                }
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,7 +83,7 @@
         ?>
         <form method="POST" id="saveLang">
             <input type="hidden" name="goDaddyGo" value="">
-            <div class="alert alert-info"><span class="glyphicon glyphicon-alert"></span> Now you edit language: <b><?= ucfirst($_GET['editLang']) ?></b></div>
+            <div class="alert alert-info"><span class="glyphicon glyphicon-alert"></span> Now you edit language: <b><?= ucfirst(htmlspecialchars($_GET['editLang'])) ?></b></div>
             <?php
             $o = 1;
             $countValuesForEdit = 0;
```
