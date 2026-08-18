# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4206_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4206_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 88-128 of the vulnerable file.

		<?php endif ?>
		<?php echo $this->BcForm->dispatchAfterForm() ?>
	</table>
</div>

<?php echo $this->BcFormTable->dispatchAfter() ?>

<div class="submit bca-actions">
	<?php if ($this->request->action == 'admin_add'): ?>
		<div class="bca-actions__main">
			<?php echo $this->BcForm->button(__d('baser', '保存'), ['div' => false, 'class' => 'button bca-btn', 'data-bca-btn-type' => 'save', 'data-bca-btn-size' => 'lg', 'data-bca-btn-width' => 'lg','id' => 'BtnSave']) ?>
		</div>
	<?php elseif ($this->request->action == 'admin_edit'): ?>
		<?php if($isWritable): ?>
			<div class="bca-actions__main">
				<?php echo $this->BcForm->button(__d('baser', '保存'), ['div' => false, 'class' => 'button bca-btn', 'data-bca-btn-type' => 'save', 'data-bca-btn-size' => 'lg', 'data-bca-btn-width' => 'lg','id' => 'BtnSave']) ?>
			</div>
			<div class="bca-actions__sub">
				<?php $this->BcBaser->link(__d('baser', '削除'), array_merge(['action' => 'del', $theme, $plugin, $type], $params), ['class' => 'submit-token button bca-btn', 'data-bca-btn-type' => 'delete', 'data-bca-btn-size' => 'sm'], sprintf(__d('baser', '%s を本当に削除してもいいですか？'), basename($path)), false) ?>
			</div>
		<?php endif ?>	
	<?php else: ?>
		<?php // プラグインのアセットの場合はコピーできない ?>
		<?php if (!$safeModeOn): ?>
			<?php //if($theme == 'core' && !(($type == 'css' || $type == 'js' || $type == 'img') && $plugin)): ?>
			<?php if ($theme == 'core'): ?>
				<?php $this->BcBaser->link(__d('baser', '現在のテーマにコピー'), array_merge(array('action' => 'copy_to_theme', $theme, $plugin, $type), explode('/', $path)), array('class' => 'submit-token btn-red button bca-btn'), sprintf(__d('baser', '本当に現在のテーマ「%s」にコピーしてもいいですか？\n既に存在するファイルは上書きされます。'), Inflector::camelize($siteConfig['theme']))); ?>
			<?php endif; ?>
		<?php else: ?>
			<?php echo __d('baser', '機能制限のセーフモードで動作していますので、現在のテーマへのコピーはできません。') ?>
		<?php endif; ?>
	<?php endif; ?>
</div>

<?php if ($this->request->action == 'admin_add' || $this->request->action == 'admin_edit'): ?>
	<?php $this->BcBaser->link(__d('baser', '一覧に戻る'), array_merge(['action' => 'index', $theme, $plugin, $type], $parentPrams), ['class' => 'btn-gray button bca-btn', 'data-bca-btn-type' => 'back-to-list']); ?>
<?php else: ?>
	<?php $this->BcBaser->link(__d('baser', '一覧に戻る'), array_merge(array('action' => 'index', $theme, $plugin, $type), explode('/', dirname($path))), array('class' => 'btn-gray button bca-btn', 'data-bca-btn-type' => 'back-to-list')); ?>
<?php endif; ?>


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -105,12 +105,13 @@
 			<div class="bca-actions__sub">
 				<?php $this->BcBaser->link(__d('baser', '削除'), array_merge(['action' => 'del', $theme, $plugin, $type], $params), ['class' => 'submit-token button bca-btn', 'data-bca-btn-type' => 'delete', 'data-bca-btn-size' => 'sm'], sprintf(__d('baser', '%s を本当に削除してもいいですか？'), basename($path)), false) ?>
 			</div>
-		<?php endif ?>	
+		<?php endif ?>
 	<?php else: ?>
 		<?php // プラグインのアセットの場合はコピーできない ?>
 		<?php if (!$safeModeOn): ?>
 			<?php //if($theme == 'core' && !(($type == 'css' || $type == 'js' || $type == 'img') && $plugin)): ?>
-			<?php if ($theme == 'core'): ?>
+			<?php // テーマ編集が許可されていない場合コピー不可 ?>
+			<?php if ($theme == 'core' && Configure::read('BcApp.allowedThemeEdit')): ?>
 				<?php $this->BcBaser->link(__d('baser', '現在のテーマにコピー'), array_merge(array('action' => 'copy_to_theme', $theme, $plugin, $type), explode('/', $path)), array('class' => 'submit-token btn-red button bca-btn'), sprintf(__d('baser', '本当に現在のテーマ「%s」にコピーしてもいいですか？\n既に存在するファイルは上書きされます。'), Inflector::camelize($siteConfig['theme']))); ?>
 			<?php endif; ?>
 		<?php else: ?>
```
