# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4206_6
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4206_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-54 of the vulnerable file.

 * [ADMIN] テーマ一覧　行
 */
?>


<li>
	<p class="theme-name"><strong><?php echo h($data['title']) ?></strong>&nbsp;(&nbsp;<?php echo $data['name'] ?>&nbsp;)</p>
	<p class="theme-screenshot">
		<a class="theme-popup" href="<?php echo '#Contents' . Inflector::camelize($data['name']) ?>">
			<?php if ($data['screenshot']): ?>
				<?php $this->BcBaser->img('/theme/' . $data['name'] . '/screenshot.png', ['alt' => $data['title']]) ?>
			<?php else: ?>
				<?php $this->BcBaser->img('admin/no-screenshot.png', ['alt' => $data['title']]) ?>
			<?php endif ?>
		</a>
	</p>
	<p class="row-tools">
		<?php if ($data['name'] != $this->BcBaser->siteConfig['theme']): ?>
			<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_apply.png', ['alt' => __d('baser', '適用'), 'class' => 'btn']), ['action' => 'apply', $data['name']], ['title' => __d('baser', '適用'), 'class' => 'submit-token']) ?>
		<?php endif ?>
		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_manage.png', ['alt' => __d('baser', 'テンプレート編集'), 'class' => 'btn']), ['controller' => 'theme_files', 'action' => 'index', $data['name']], ['title' => __d('baser', 'テンプレート編集')]) ?>
		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_copy.png', ['alt' => __d('baser', 'テーマコピー'), 'class' => 'btn']), ['action' => 'ajax_copy', $data['name']], ['title' => __d('baser', 'テーマコピー'), 'class' => 'btn-copy']) ?>
		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_delete.png', ['alt' => __d('baser', 'テーマ削除'), 'class' => 'btn']), ['action' => 'ajax_delete', $data['name']], ['title' => __d('baser', 'テーマ削除'), 'class' => 'btn-delete']) ?>
</p>
<p class="theme-version"><?php echo __d('baser', 'バージョン')?>：<?php echo $data['version'] ?></p>
<p class="theme-author"><?php echo __d('baser', '制作者')?>：
	<?php if (!empty($data['url']) && !empty($data['author'])): ?>
		<?php $this->BcBaser->link($data['author'], $data['url'], ['target' => '_blank', 'escape' => true]) ?>
	<?php else: ?>
		<?php echo h($data['author']) ?>
	<?php endif ?>
</p>
<div style='display:none'>
	<div id="<?php echo 'Contents' . Inflector::camelize($data['name']) ?>" class="theme-popup-contents clearfix">
		<div class="theme-screenshot">
			<?php if ($data['screenshot']): ?>
				<?php $this->BcBaser->img('/theme/' . $data['name'] . '/screenshot.png', ['alt' => $data['title']]) ?>
			<?php else: ?>
				<?php $this->BcBaser->img('admin/no-screenshot.png', ['alt' => $data['title']]) ?>
			<?php endif ?>
		</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,9 @@
 		<?php if ($data['name'] != $this->BcBaser->siteConfig['theme']): ?>
 			<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_apply.png', ['alt' => __d('baser', '適用'), 'class' => 'btn']), ['action' => 'apply', $data['name']], ['title' => __d('baser', '適用'), 'class' => 'submit-token']) ?>
 		<?php endif ?>
-		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_manage.png', ['alt' => __d('baser', 'テンプレート編集'), 'class' => 'btn']), ['controller' => 'theme_files', 'action' => 'index', $data['name']], ['title' => __d('baser', 'テンプレート編集')]) ?>
+		<?php if (Configure::read('BcApp.allowedThemeEdit')): ?>
+			<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_manage.png', ['alt' => __d('baser', 'テンプレート編集'), 'class' => 'btn']), ['controller' => 'theme_files', 'action' => 'index', $data['name']], ['title' => __d('baser', 'テンプレート編集')]) ?>
+		<?php endif; ?>
 		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_copy.png', ['alt' => __d('baser', 'テーマコピー'), 'class' => 'btn']), ['action' => 'ajax_copy', $data['name']], ['title' => __d('baser', 'テーマコピー'), 'class' => 'btn-copy']) ?>
 		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_delete.png', ['alt' => __d('baser', 'テーマ削除'), 'class' => 'btn']), ['action' => 'ajax_delete', $data['name']], ['title' => __d('baser', 'テーマ削除'), 'class' => 'btn-delete']) ?>
 </p>
```
