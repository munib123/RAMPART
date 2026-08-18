# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4206_5
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4206_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 18-58 of the vulnerable file.


<script type="text/javascript">
$(function(){
	$(".theme-popup").colorbox({inline:true, width:"60%"});
});
</script>


<div id="CurrentTheme" class="clearfix">
	<h2><?php echo __d('baser', '現在のテーマ')?></h2>
	<?php if ($currentTheme): ?>
		<div class="current-theme-left">
			<div class="theme-screenshot">
				<?php if ($currentTheme['screenshot']): ?>
					<?php $this->BcBaser->img('/theme/' . $currentTheme['name'] . '/screenshot.png', ['alt' => $currentTheme['title']]) ?>
				<?php else: ?>
					<?php $this->BcBaser->img('admin/no-screenshot.png', ['alt' => $currentTheme['title']]) ?>
				<?php endif ?>
			</div>
			<p class="row-tools">
				<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_manage.png', ['alt' => __d('baser', 'テンプレート編集'), 'class' => 'btn']), ['controller' => 'theme_files', 'action' => 'index', $currentTheme['name']], ['title' => __d('baser', 'テンプレート編集')]) ?>
				<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_copy.png', ['alt' => __d('baser', 'テーマコピー'), 'class' => 'btn']), ['action' => 'ajax_copy', $currentTheme['name']], ['title' => __d('baser', 'テーマコピー'), 'class' => 'btn-copy']) ?>
			</p>
		</div>

		<div class="theme-info">
			<p class="theme-name"><strong><?php echo h($currentTheme['title']) ?></strong>&nbsp;(&nbsp;<?php echo $currentTheme['name'] ?>&nbsp;)</p>
			<p class="theme-version"><?php echo __d('baser', 'バージョン')?>：<?php echo $currentTheme['version'] ?></p>
			<p class="theme-author"><?php echo __d('baser', '制作者')?>：<?php if (!empty($currentTheme['url']) && !empty($currentTheme['author'])): ?>
					<?php $this->BcBaser->link($currentTheme['author'], $currentTheme['url'], ['target' => '_blank', 'escape' => true]) ?>
				<?php else: ?>
					<?php echo h($currentTheme['author']) ?>
				<?php endif ?>
			</p>
		</div>
		<br /><br />
		<?php if ($defaultDataPatterns && $this->BcBaser->isAdminUser()): ?>
			<?php echo $this->BcForm->create('Theme', ['url' => ['action' => 'load_default_data_pattern']]) ?>
			<?php echo $this->BcForm->input('Theme.default_data_pattern', ['type' => 'select', 'options' => $defaultDataPatterns]) ?>
			<?php echo $this->BcForm->submit(__d('baser', '初期データ読込'), ['class' => 'button-small', 'div' => false, 'id' => 'BtnLoadDefaultDataPattern']) ?>
			<?php echo $this->BcForm->end() ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -35,7 +35,9 @@
 				<?php endif ?>
 			</div>
 			<p class="row-tools">
-				<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_manage.png', ['alt' => __d('baser', 'テンプレート編集'), 'class' => 'btn']), ['controller' => 'theme_files', 'action' => 'index', $currentTheme['name']], ['title' => __d('baser', 'テンプレート編集')]) ?>
+				<?php if (Configure::read('BcApp.allowedThemeEdit')): ?>
+					<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_manage.png', ['alt' => __d('baser', 'テンプレート編集'), 'class' => 'btn']), ['controller' => 'theme_files', 'action' => 'index', $currentTheme['name']], ['title' => __d('baser', 'テンプレート編集')]) ?>
+				<?php endif; ?>
 				<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_copy.png', ['alt' => __d('baser', 'テーマコピー'), 'class' => 'btn']), ['action' => 'ajax_copy', $currentTheme['name']], ['title' => __d('baser', 'テーマコピー'), 'class' => 'btn-copy']) ?>
 			</p>
 		</div>
```
