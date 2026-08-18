# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 223_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `223_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-31 of the vulnerable file.

<div id="tag-form" class="field">
    <?php
        $tags = $item->getTags();
    ?>
    <input type="hidden" name="tags-to-add" id="tags-to-add" value="" />
    <input type="hidden" name="tags-to-delete" id="tags-to-delete" value="" />
    <div id="add-tags">
        <label><?php echo __('Add Tags'); ?></label>           
        <input type="text" name="tags" size="20" id="tags" class="textinput" value="" />
        <p id="add-tags-explanation" class="explanation"><?php echo __('Separate tags with %s', option('tag_delimiter')); ?></p>
        <input type="submit" name="add-tags-button" id="add-tags-button" class="green button" value="<?php echo __('Add Tags'); ?>" />
    </div>
    <div id="all-tags">
    <?php if ($tags): ?>
        <h3><?php echo __('All Tags'); ?></h3>
        
        <div class="tag-list">
        <ul id="all-tags-list">
            <?php foreach( $tags as $tag ): ?>
                <li>
                    <?php echo '<span class="tag">' . $tag->name . '</span>'; 
                          echo '<span class="undo-remove-tag"><a href="#">' . __('Undo') . '</a></span>';
                          echo '<span class="remove-tag"><a href="#">' . __('Remove') . '</a></span>'; ?>
                </li>
            <?php endforeach; ?>
        </ul>
        </div>
    <?php endif; ?>
    </div>
</div>
<?php fire_plugin_hook('admin_items_form_tags', array('item' => $item, 'view' => $this)); ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,7 +18,7 @@
         <ul id="all-tags-list">
             <?php foreach( $tags as $tag ): ?>
                 <li>
-                    <?php echo '<span class="tag">' . $tag->name . '</span>'; 
+                    <?php echo '<span class="tag">' . html_escape($tag->name) . '</span>';
                           echo '<span class="undo-remove-tag"><a href="#">' . __('Undo') . '</a></span>';
                           echo '<span class="remove-tag"><a href="#">' . __('Remove') . '</a></span>'; ?>
                 </li>
```
