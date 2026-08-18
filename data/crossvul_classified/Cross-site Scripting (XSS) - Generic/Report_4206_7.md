# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4206_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4206_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 85-120 of the vulnerable file.

						<?php endif ?>
					<?php endif ?>
				</td>
			</tr>
		<?php endif ?>
		<?php echo $this->BcForm->dispatchAfterForm() ?>
	</table>
</div>

<?php echo $this->BcFormTable->dispatchAfter() ?>

<div class="submit">
	<?php if ($this->request->action == 'admin_add'): ?>
		<?php $this->BcBaser->link(__d('baser', '一覧に戻る'), array_merge(['action' => 'index', $theme, $plugin, $type], $parentPrams), ['class' => 'btn-gray button']); ?>
		<?php echo $this->BcForm->submit(__d('baser', '保存'), ['div' => false, 'class' => 'button', 'id' => 'BtnSave']) ?>
	<?php elseif ($this->request->action == 'admin_edit'): ?>
		<?php $this->BcBaser->link(__d('baser', '一覧に戻る'), array_merge(['action' => 'index', $theme, $plugin, $type], $parentPrams), ['class' => 'btn-gray button']); ?>
		<?php if($isWritable): ?>
			<?php echo $this->BcForm->submit(__d('baser', '保存'), ['div' => false, 'class' => 'button', 'id' => 'BtnSave']) ?>
			<?php $this->BcBaser->link(__d('baser', '削除'), array_merge(['action' => 'del', $theme, $plugin, $type], $params), ['class' => 'submit-token button'], sprintf(__d('baser', '%s を本当に削除してもいいですか？'), basename($path)), false) ?>
		<?php endif ?>	
	<?php else: ?>
		<?php $this->BcBaser->link(__d('baser', '一覧に戻る'), array_merge(['action' => 'index', $theme, $plugin, $type], $parentPrams), ['class' => 'btn-gray button']); ?>
		<?php // プラグインのアセットの場合はコピーできない ?>
		<?php if (!$safeModeOn): ?>
			<?php //if($theme == 'core' && !(($type == 'css' || $type == 'js' || $type == 'img') && $plugin)): ?>
			<?php if ($theme == 'core'): ?>
				<?php $this->BcBaser->link(__d('baser', '現在のテーマにコピー'), array_merge(['action' => 'copy_to_theme', $theme, $plugin, $type], explode('/', $path)), ['class' => 'submit-token btn-red button'], sprintf(__d('baser', "本当に現在のテーマ「 %s 」にコピーしてもいいですか？\n既に存在するファイルは上書きされます。"), Inflector::camelize($siteConfig['theme']))); ?>
			<?php endif; ?>
		<?php else: ?>
            <?php echo __d('baser', '機能制限のセーフモードで動作していますので、現在のテーマへのコピーはできません。')?>
		<?php endif; ?>
	<?php endif; ?>
</div>

<?php echo $this->BcForm->end() ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,13 +102,14 @@
 		<?php if($isWritable): ?>
 			<?php echo $this->BcForm->submit(__d('baser', '保存'), ['div' => false, 'class' => 'button', 'id' => 'BtnSave']) ?>
 			<?php $this->BcBaser->link(__d('baser', '削除'), array_merge(['action' => 'del', $theme, $plugin, $type], $params), ['class' => 'submit-token button'], sprintf(__d('baser', '%s を本当に削除してもいいですか？'), basename($path)), false) ?>
-		<?php endif ?>	
+		<?php endif ?>
 	<?php else: ?>
 		<?php $this->BcBaser->link(__d('baser', '一覧に戻る'), array_merge(['action' => 'index', $theme, $plugin, $type], $parentPrams), ['class' => 'btn-gray button']); ?>
 		<?php // プラグインのアセットの場合はコピーできない ?>
 		<?php if (!$safeModeOn): ?>
 			<?php //if($theme == 'core' && !(($type == 'css' || $type == 'js' || $type == 'img') && $plugin)): ?>
-			<?php if ($theme == 'core'): ?>
+			<?php // テーマ編集が許可されていない場合コピー不可 ?>
+			<?php if ($theme == 'core' && Configure::read('BcApp.allowedThemeEdit')): ?>
 				<?php $this->BcBaser->link(__d('baser', '現在のテーマにコピー'), array_merge(['action' => 'copy_to_theme', $theme, $plugin, $type], explode('/', $path)), ['class' => 'submit-token btn-red button'], sprintf(__d('baser', "本当に現在のテーマ「 %s 」にコピーしてもいいですか？\n既に存在するファイルは上書きされます。"), Inflector::camelize($siteConfig['theme']))); ?>
 			<?php endif; ?>
 		<?php else: ?>
```
