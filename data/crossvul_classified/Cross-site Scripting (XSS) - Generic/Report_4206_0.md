# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4206_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4206_0`)

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

<div id="CurrentTheme" class="bca-current-theme">
	<h2 class="bca-current-theme__name"><?php echo __d('baser', '現在のテーマ') ?></h2>
	<?php if ($currentTheme): ?>
    <div class="bca-current-theme__inner">
      <div class="bca-current-theme__main">
        <div class="bca-current-theme__screenshot">
          <?php if ($currentTheme['screenshot']): ?>
            <?php $this->BcBaser->img('/theme/' . $currentTheme['name'] . '/screenshot.png', ['alt' => $currentTheme['title']]) ?>
          <?php else: ?>
            <?php $this->BcBaser->img('admin/no-screenshot.png', ['alt' => $currentTheme['title']]) ?>
          <?php endif ?>
        </div>
        <div class="row-tools">
          <?php $this->BcBaser->link('', ['controller' => 'theme_files', 'action' => 'index', $currentTheme['name']], ['title' => __d('baser', 'テンプレート編集'), 'class' => 'bca-btn-icon', 'data-bca-btn-type' => 'file-list', 'data-bca-btn-size' => 'lg']) ?>
          <?php $this->BcBaser->link('', ['action' => 'ajax_copy', $currentTheme['name']], ['title' => __d('baser', 'テーマコピー'), 'class' => 'btn-copy bca-btn-icon', 'data-bca-btn-type' => 'copy', 'data-bca-btn-size' => 'lg']) ?>
        </div>
      </div>

      <div class="bca-current-theme__sub">
        <div class="theme-info">
          <h3 class="theme-name"><strong><?php echo h($currentTheme['title']) ?></strong>&nbsp;(&nbsp;<?php echo $currentTheme['name'] ?>&nbsp;)</h3>
          <p class="theme-version"><?php echo __d('baser', 'バージョン') ?>：<?php echo $currentTheme['version'] ?></p>
          <p class="theme-author"><?php echo __d('baser', '制作者') ?>：<?php if (!empty($currentTheme['url']) && !empty($currentTheme['author'])): ?>
              <?php $this->BcBaser->link($currentTheme['author'], $currentTheme['url'], ['target' => '_blank', 'escape' => true]) ?>
            <?php else: ?>
              <?php echo h($currentTheme['author']) ?>
            <?php endif ?>
          </p>
        </div>
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
         <div class="row-tools">
-          <?php $this->BcBaser->link('', ['controller' => 'theme_files', 'action' => 'index', $currentTheme['name']], ['title' => __d('baser', 'テンプレート編集'), 'class' => 'bca-btn-icon', 'data-bca-btn-type' => 'file-list', 'data-bca-btn-size' => 'lg']) ?>
+			<?php if (Configure::read('BcApp.allowedThemeEdit')): ?>
+        		<?php $this->BcBaser->link('', ['controller' => 'theme_files', 'action' => 'index', $currentTheme['name']], ['title' => __d('baser', 'テンプレート編集'), 'class' => 'bca-btn-icon', 'data-bca-btn-type' => 'file-list', 'data-bca-btn-size' => 'lg']) ?>
+			<?php endif; ?>
           <?php $this->BcBaser->link('', ['action' => 'ajax_copy', $currentTheme['name']], ['title' => __d('baser', 'テーマコピー'), 'class' => 'btn-copy bca-btn-icon', 'data-bca-btn-type' => 'copy', 'data-bca-btn-size' => 'lg']) ?>
         </div>
       </div>
```
