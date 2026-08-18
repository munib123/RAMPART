# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4122_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4122_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 8-48 of the vulnerable file.

 * @package			Baser.View
 * @since			baserCMS v 0.1.0
 * @license			https://basercms.net/license/index.html
 */

/**
 * [ADMIN] テーマフォルダ登録・編集
 *
 * @var BcAppView $this
 */
$this->BcBaser->js('admin/theme_files/form_folder');
$parentPrams = $params = explode('/', $path);
if ($this->request->action !== 'admin_add_folder') {
	unset($parentPrams[count($parentPrams)-1]);
}
?>


<!-- current -->
<div class="em-box bca-current-box">
	<?php echo __d('baser', '現在の位置')?>：<?php echo $currentPath ?>
</div>

<?php if ($this->request->action == 'admin_add_folder'): ?>
	<?php echo $this->BcForm->create('ThemeFolder', ['id' => 'TemplateForm', 'url' => array_merge(['controller' => 'theme_files', 'action' => 'add_folder', $theme, $type], $params)]) ?>
<?php else: ?>
	<?php echo $this->BcForm->create('ThemeFolder', ['id' => 'TemplateForm', 'url' => array_merge(['controller' => 'theme_files', 'action' => 'edit_folder', $theme, $type], $params)]) ?>
<?php endif ?>

<?php echo $this->BcFormTable->dispatchBefore() ?>

<?php if($theme	!= 'core' && !$isWritable): ?>
	<div id="AlertMessage">ファイルに書き込み権限がないので編集できません。</div>
<?php endif ?>

<?php echo $this->BcForm->input('ThemeFolder.parent', ['type' => 'hidden']) ?>
<?php echo $this->BcForm->input('ThemeFolder.pastname', ['type' => 'hidden']) ?>

<!-- form -->
<div class="section">
	<table cellpadding="0" cellspacing="0" id="FormTable" class="form-table bca-form-table">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
 
 <!-- current -->
 <div class="em-box bca-current-box">
-	<?php echo __d('baser', '現在の位置')?>：<?php echo $currentPath ?>
+	<?php echo __d('baser', '現在の位置')?>：<?php echo h($currentPath) ?>
 </div>
 
 <?php if ($this->request->action == 'admin_add_folder'): ?>
```
