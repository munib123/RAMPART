# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4122_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4122_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 28-68 of the vulnerable file.



<script type="text/javascript">
$(function(){
	$("#ThemeFileFile").change(function(){
		$("#Waiting").show();
		$("#ThemeFileUpload").submit();
	});
	$.baserAjaxDataList.init();
	$.baserAjaxBatch.init({ url: $("#AjaxBatchUrl").html()});
});
</script>

<?php $this->BcBaser->element('submenus/theme_files'); ?>

<div id="AjaxBatchUrl" style="display:none"><?php $this->BcBaser->url(array_merge(['controller' => 'theme_files', 'action' => 'ajax_batch', $theme, $type], $params)) ?></div>
<div id="AlertMessage" class="message" style="display:none"></div>
<div id="MessageBox" style="display:none"><div id="flashMessage" class="notice-message"></div></div>

<!-- current -->
<div class="em-box bca-current-box"><?php echo __d('baser', '現在の位置') ?>：<?php echo $currentPath ?>
	<?php if (!$writable): ?>
		　<span style="color:#FF3300">[<?php echo __d('baser', '書込不可') ?>]</span>
	<?php endif ?>
</div>

<div id="DataList" class="bca-data-list"><?php $this->BcBaser->element('theme_files/index_list') ?></div>

<div class="bca-actions" data-bca-type="type2">
	<?php if ($writable): ?>
  <div class="bca-actions__form">
		<?php echo $this->BcForm->create('ThemeFile', ['id' => 'ThemeFileUpload', 'url' => array_merge(['action' => 'upload', $theme, $plugin, $type], $params), 'enctype' => 'multipart/form-data']) ?>
		  <?php echo $this->BcForm->input('ThemeFile.file', ['type' => 'file']) ?>
		<?php echo $this->BcForm->end() ?>
  </div>
  <?php endif ?>
  <div class="bca-actions__adds">
    <?php if ($writable): ?>
		<?php $this->BcBaser->link('<i class="bca-icon--folder"></i> ' . __d('baser', 'フォルダ新規作成'), array_merge(['action' => 'add_folder', $theme, $type], $params),
      [
        'class' => 'bca-btn',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,7 +45,7 @@
 <div id="MessageBox" style="display:none"><div id="flashMessage" class="notice-message"></div></div>
 
 <!-- current -->
-<div class="em-box bca-current-box"><?php echo __d('baser', '現在の位置') ?>：<?php echo $currentPath ?>
+<div class="em-box bca-current-box"><?php echo __d('baser', '現在の位置') ?>：<?php echo h($currentPath) ?>
 	<?php if (!$writable): ?>
 		　<span style="color:#FF3300">[<?php echo __d('baser', '書込不可') ?>]</span>
 	<?php endif ?>
```
