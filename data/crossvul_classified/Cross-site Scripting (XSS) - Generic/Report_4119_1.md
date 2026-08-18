# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4119_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4119_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 30-70 of the vulnerable file.

}
if (!empty($currentAuthPrefix['name']) && $currentPrefix != 'front') {
	$authName = $currentAuthPrefix['name'];
} elseif (isset($this->BcBaser->siteConfig['formal_name'])) {
	$authName = $this->BcBaser->siteConfig['formal_name'];
} else {
	$authName = '';
}
?>


<div id="ToolBar">
	<div id="ToolbarInner" class="clearfix">
		<div id="ToolMenu">
			<ul>
				<?php if ($this->name == 'Installations'): ?>
					<li><?php $this->BcBaser->link(__d('baser', 'インストールマニュアル'), 'http://wiki.basercms.net/%E3%82%A4%E3%83%B3%E3%82%B9%E3%83%88%E3%83%BC%E3%83%AB%E3%82%AC%E3%82%A4%E3%83%89', ['target' => '_blank', 'class' => 'tool-menu']) ?></li>
				<?php elseif (Configure::read('BcRequest.isUpdater')): ?>
					<li><?php $this->BcBaser->link(__d('baser', 'アップデートマニュアル'), 'http://wiki.basercms.net/%E3%83%90%E3%83%BC%E3%82%B8%E3%83%A7%E3%83%B3%E3%82%A2%E3%83%83%E3%83%97%E3%82%AC%E3%82%A4%E3%83%89', ['target' => '_blank', 'class' => 'tool-menu']) ?></li>
				<?php elseif (!empty($this->request->params['admin']) || ('/' . $this->request->url) == $loginUrl): ?>	
					<li><?php $this->BcBaser->link($this->BcBaser->siteConfig['formal_name'], '/') ?></li>
				<?php else: ?>
					<?php if (in_array('admin', $currentUserAuthPrefixes)): ?>
						<li><?php $this->BcBaser->link($this->BcBaser->getImg('admin/btn_logo.png', ['alt' => __d('baser', 'baserCMS管理システム'), 'class' => 'bc-btn']), ['plugin' => null, 'admin' => true, 'controller' => 'dashboard', 'action' => 'index'], ['title' => __d('baser', 'baserCMS管理システム')]) ?></li>
					<?php else: ?>
						<li><?php $this->BcBaser->link($authName, Configure::read('BcAuthPrefix.' . $currentPrefix . '.loginRedirect'), ['title' => $authName]) ?></li>
					<?php endif ?>
				<?php endif ?>
				<?php if ($this->BcBaser->existsEditLink() && !isset($this->request->query['preview'])): ?>
					<li><?php $this->BcBaser->editLink() ?></li>
				<?php endif ?>
				<?php if ($this->BcBaser->existsPublishLink()): ?>
					<li><?php $this->BcBaser->publishLink() ?></li>
				<?php endif ?>
				<?php if (!$loginUrl || $this->request->url != $loginUrl): ?>
					<?php if (Configure::read('debug') == -1 && $this->name != "Installations"): ?>
						<li>&nbsp;&nbsp;<span id="DebugMode" title="<?php echo __d('baser', 'インストールモードです。運営を開始する前にシステム設定よりノーマルモードに戻しましょう。') ?>"><?php echo __d('baser', 'インストールモード') ?></span>&nbsp;&nbsp;</li>
					<?php elseif (Configure::read('debug') > 0): ?>
						<li>&nbsp;&nbsp;<span id="DebugMode" title="<?php echo __d('baser', 'デバッグモードです。運営を開始する前にシステム設定よりノーマルモードに戻しましょう。') ?>"><?php echo __d('baser', 'デバッグモード') ?> <?php echo mb_convert_kana(Configure::read('debug'), 'N') ?></span>&nbsp;&nbsp;</li>
					<?php endif; ?>
				<?php endif ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,12 +47,12 @@
 				<?php elseif (Configure::read('BcRequest.isUpdater')): ?>
 					<li><?php $this->BcBaser->link(__d('baser', 'アップデートマニュアル'), 'http://wiki.basercms.net/%E3%83%90%E3%83%BC%E3%82%B8%E3%83%A7%E3%83%B3%E3%82%A2%E3%83%83%E3%83%97%E3%82%AC%E3%82%A4%E3%83%89', ['target' => '_blank', 'class' => 'tool-menu']) ?></li>
 				<?php elseif (!empty($this->request->params['admin']) || ('/' . $this->request->url) == $loginUrl): ?>	
-					<li><?php $this->BcBaser->link($this->BcBaser->siteConfig['formal_name'], '/') ?></li>
+					<li><?php $this->BcBaser->link($this->BcBaser->siteConfig['formal_name'], '/', ['escape' => true]) ?></li>
 				<?php else: ?>
 					<?php if (in_array('admin', $currentUserAuthPrefixes)): ?>
 						<li><?php $this->BcBaser->link($this->BcBaser->getImg('admin/btn_logo.png', ['alt' => __d('baser', 'baserCMS管理システム'), 'class' => 'bc-btn']), ['plugin' => null, 'admin' => true, 'controller' => 'dashboard', 'action' => 'index'], ['title' => __d('baser', 'baserCMS管理システム')]) ?></li>
 					<?php else: ?>
-						<li><?php $this->BcBaser->link($authName, Configure::read('BcAuthPrefix.' . $currentPrefix . '.loginRedirect'), ['title' => $authName]) ?></li>
+						<li><?php $this->BcBaser->link($authName, Configure::read('BcAuthPrefix.' . $currentPrefix . '.loginRedirect'), ['title' => $authName, 'escape' => ture]) ?></li>
 					<?php endif ?>
 				<?php endif ?>
 				<?php if ($this->BcBaser->existsEditLink() && !isset($this->request->query['preview'])): ?>
```
