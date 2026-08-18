# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 491_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `491_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 109-149 of the vulnerable file.

                <br/>
                <?php if (Permission::model()->hasGlobalPermission('templates','update')) {
                    $sSaveText = ( $oEditedTemplate->getTemplateForFile($relativePathEditfile, $oEditedTemplate)->sTemplateName == $oEditedTemplate->sTemplateName)
                        ? gT("Save changes")
                        : gT("Copy to local theme and save changes");
                    if (is_writable($templates[$templatename])) { ?>
                        <input type='submit' class='btn btn-default' id='button-save-changes' value='<?php echo $sSaveText; ?>' <?=(!is_template_editable($templatename) ? "disabled='disabled' alt='".gT( "Changes cannot be saved to a standard theme."). "'" : "")?> />
                    <?php } ?>
                <?php } ?>
            </p>
        </form>
    </div>
    <div class="col-lg-2" style="overflow-x: hidden">
        <div>
            <?php eT("Other files:"); ?>
            <br/>
            <div class="col-sm-12 well other-files-list">
                <?php foreach ($otherfiles as $fileName => $file) { ?>
                    <div class="row other-files-row">
                        <div class="col-sm-9 other-files-filename">
                            <?php echo (empty(substr(strrchr($file, DIRECTORY_SEPARATOR), 1)))?$file:substr(strrchr($file, DIRECTORY_SEPARATOR), 1) ;?>
                        </div>
                        <div class="col-sm-3">
                            <?php //TODO: make it ajax and less messy ?>
                            <?php if ( $oEditedTemplate->getTemplateForFile($fileName, $oEditedTemplate)->sTemplateName == $oEditedTemplate->sTemplateName) {
                                if (Permission::model()->hasGlobalPermission('templates','delete')) { ?>
                                    <?=CHtml::form(array('admin/themes/sa/templatefiledelete'), 'post'); ?>
                                        <input type='hidden' name="otherfile" value="<?php echo $file; ?>" />
                                        <input type='submit' class='btn btn-default btn-xs other-files-delete-button' value='<?php eT("Delete"); ?>' onclick="javascript:return confirm('<?php eT(" Are you sure you want to delete this file? ", "js"); ?>')"/>
                                        <input type='hidden' name='screenname' value='<?php echo htmlspecialchars($screenname); ?>' />
                                        <input type='hidden' name='templatename' value='<?php echo htmlspecialchars($templatename); ?>' />
                                        <input type='hidden' name='editfile' value='<?php echo htmlspecialchars($relativePathEditfile); ?>' />
                                        <input type='hidden' name='action' value='templatefiledelete' />
                                    </form>
                                <?php } ?>
                            <?php } else { ?>
                                <span class="label label-danger"><?php eT("inherited"); ?></span>
                            <?php }?>
                        </div>
                    </div>
                <?php }?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -126,7 +126,7 @@
                 <?php foreach ($otherfiles as $fileName => $file) { ?>
                     <div class="row other-files-row">
                         <div class="col-sm-9 other-files-filename">
-                            <?php echo (empty(substr(strrchr($file, DIRECTORY_SEPARATOR), 1)))?$file:substr(strrchr($file, DIRECTORY_SEPARATOR), 1) ;?>
+                            <?php echo CHtml::encode((empty(substr(strrchr($file, DIRECTORY_SEPARATOR), 1)))?$file:substr(strrchr($file, DIRECTORY_SEPARATOR), 1)) ;?>
                         </div>
                         <div class="col-sm-3">
                             <?php //TODO: make it ajax and less messy ?>
```
