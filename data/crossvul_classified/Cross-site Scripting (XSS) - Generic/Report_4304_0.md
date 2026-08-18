# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4304_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4304_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 42-82 of the vulnerable file.

                 . "<input name=\"ParticipantAttributeName[visible]\" id=\"ParticipantAttributeName_visible\" type=\"radio\" value=\"FALSE\" "
                    .($model->visible == "FALSE" ? "checked" : "")." />"
                 . gT("No")."
                </label>
            </div>
        </div>
        <br/>"; 
    ?>
    <div id="ParticipantAttributeNamesDropdownEdit" class="row form-group" style="display: none;">
        <div class="row">
            <div class="col-xs-2">
                <button class="btn btn-default btn-block" id="addDropdownField" data-toggle="tooltip" title="<?php eT('Add dropdown field'); ?>"><i class="fa fa-plus-circle text-success"></i></button>
            </div>
            <h4 class="col-xs-8 col-offset-xs-2"><?php eT("Dropdown fields") ?></h4>
        </div>
        <div id='ParticipantAttributeNamesDropdownEditList'>
            <?php 
                foreach($model->getAttributesValues($model->attribute_id) as $attribute_value){
                    echo "<div class='control-group'>";
                    echo "<div class='dropDownContainer col-xs-8 col-offset-xs-2'>";
                    echo "<input class='form-control' name='ParticipantAttributeNamesDropdown[]' value='".$attribute_value['value']."' />";
                    echo "</div>";
                    echo '<div class="col-xs-1">
                            <button class="btn btn-default form-group action_delDropdownField">
                                <i class="fa fa-trash text-danger"></i>
                            </button>
                        </div>
                    </div>';
                }
            ?>
            <div class='control-group'>
                <div class='dropDownContainer col-xs-8 col-offset-xs-2'>
                    <input class='form-control' name='ParticipantAttributeNamesDropdown[]' value='' />
                </div>
                <div class="col-xs-1">
                    <button class="btn btn-default form-group action_delDropdownField">
                        <i class="fa fa-trash text-danger"></i>
                    </button>
                </div>
            </div>
        </div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,7 +59,11 @@
                 foreach($model->getAttributesValues($model->attribute_id) as $attribute_value){
                     echo "<div class='control-group'>";
                     echo "<div class='dropDownContainer col-xs-8 col-offset-xs-2'>";
-                    echo "<input class='form-control' name='ParticipantAttributeNamesDropdown[]' value='".$attribute_value['value']."' />";
+                    echo TbHtml::textField('ParticipantAttributeNamesDropdown[]', $attribute_value['value'], [
+                        'class' => 'form-control',
+                        'id' => ''
+                    ]);
+                    // echo "<input class='form-control' name='ParticipantAttributeNamesDropdown[]' value='".$attribute_value['value']."' />";
                     echo "</div>";
                     echo '<div class="col-xs-1">
                             <button class="btn btn-default form-group action_delDropdownField">
```
