# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4454_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4454_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<div id="ajaxTemplateElementsIndex">
    <h2><?php echo __('Template Elements');?></h2>
    <ul <?php if ($mayModify): ?> id="sortable" <?php endif; ?> style="list-style:none; margin:0px;">
                <?php
                foreach ($elements as $k => $element):
                    echo $this->element('templateElements/templateRow' . ucfirst($element['TemplateElement']['element_definition']), array('element' => $element, 'element_id' => $element['TemplateElement']['id']));
                endforeach;
            ?>
    </ul>
    <?php if ($mayModify): ?>
    <div id="AddTemplateElementDiv" role="button" tabindex="0" aria-label="<?php echo __('Add a new template element');?>" title="<?php echo __('Add a new template element');?>" class="addTemplateElement useCursorPointer" onClick="templateAddElementClicked(<?php echo $id; ?>);">+</div>
    <?php endif; ?>
</div>
<script type="text/javascript">
$(function() {
    //Return a helper with preserved width of cells
    var fixHelper = function(e, ui) {
        ui.children().each(function() {
            $(this).width($(this).width());
        });
        return ui;
    };

    $("#sortable").sortable({
        helper: fixHelper,
        update: function () {
            var order = [];

            $("#sortable").children().each(function (i) {
                var li = $(this);
                order[i] = li.attr("id");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,7 @@
             ?>
     </ul>
     <?php if ($mayModify): ?>
-    <div id="AddTemplateElementDiv" role="button" tabindex="0" aria-label="<?php echo __('Add a new template element');?>" title="<?php echo __('Add a new template element');?>" class="addTemplateElement useCursorPointer" onClick="templateAddElementClicked(<?php echo $id; ?>);">+</div>
+    <div id="AddTemplateElementDiv" role="button" tabindex="0" aria-label="<?php echo __('Add a new template element');?>" title="<?php echo __('Add a new template element');?>" class="addTemplateElement useCursorPointer" onClick="templateAddElementClicked(<?php echo h($id); ?>);">+</div>
     <?php endif; ?>
 </div>
 <script type="text/javascript">
```
