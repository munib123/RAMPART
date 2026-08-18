# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4119_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4119_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 22-64 of the vulnerable file.

	$loginUrl = preg_replace('/^\//', '', $currentAuthPrefix['loginAction']);
}
if (in_array('admin', $currentUserAuthPrefixes)) {
	$logoutAction = Configure::read('BcAuthPrefix.admin.logoutAction');
} else {
	$logoutAction = Hash::get((array)$currentAuthPrefix, 'logoutAction');
}
if (!empty($currentAuthPrefix['name']) && $currentPrefix != 'front') {
	$authName = $currentAuthPrefix['name'];
} elseif (isset($this->BcBaser->siteConfig['formal_name'])) {
	$authName = $this->BcBaser->siteConfig['formal_name'];
} else {
	$authName = '';
}
?>


<div id="ToolBar" class="bca-toolbar">
	<div id="ToolbarInner" class="clearfix bca-toolbar__body">
		<div class="bca-toolbar__logo">
			<?php
				# インストール画面
				if ($this->name == 'Installations'): ?>
				<?php $this->BcBaser->link(
						$this->BcBaser->getImg('admin/logo_icon.svg', ['alt' => '', 'width' => '24', 'height' => '21', 'class' => 'bca-toolbar__logo-symbol']) . 
				        '<span class="bca-toolbar__logo-text">' . __d('baser', 'インストールマニュアル') . '</span>', 
                        'https://basercms.net/manuals/introductions/4.html', ['target' => '_blank', 'class' => 'bca-toolbar__logo-link']) ?>
			<?php
				# バージョンアップ画面
				elseif (Configure::read('BcRequest.isUpdater')): ?>
				<?php $this->BcBaser->link(
						$this->BcBaser->getImg('admin/logo_icon.svg', ['alt' => '', 'width' => '24', 'height' => '21', 'class' => 'bca-toolbar__logo-symbol']) .
						'<span class="bca-toolbar__logo-text">' . __d('baser', 'アップデートマニュアル') . '</span>', 
                        'https://basercms.net/manuals/introductions/8.html', ['target' => '_blank', 'class' => 'bca-toolbar__logo-link']) ?>
			<?php
				# 通常
				elseif (!empty($this->request->params['admin']) || ('/' . $this->request->url) == $loginUrl): ?>
				<?php
					$this->BcBaser->link(
						$this->BcBaser->getImg('admin/logo_icon.svg', ['alt' => '', 'width' => '24', 'height' => '21', 'class' => 'bca-toolbar__logo-symbol'])
							.'<span class="bca-toolbar__logo-text">'
							.$this->BcBaser->siteConfig['formal_name']
							.'</span>', '/'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,52 +39,54 @@
 <div id="ToolBar" class="bca-toolbar">
 	<div id="ToolbarInner" class="clearfix bca-toolbar__body">
 		<div class="bca-toolbar__logo">
-			<?php
-				# インストール画面
-				if ($this->name == 'Installations'): ?>
+			<?php // インストール画面 ?>
+			<?php if ($this->name == 'Installations'): ?>
 				<?php $this->BcBaser->link(
 						$this->BcBaser->getImg('admin/logo_icon.svg', ['alt' => '', 'width' => '24', 'height' => '21', 'class' => 'bca-toolbar__logo-symbol']) . 
 				        '<span class="bca-toolbar__logo-text">' . __d('baser', 'インストールマニュアル') . '</span>', 
-                        'https://basercms.net/manuals/introductions/4.html', ['target' => '_blank', 'class' => 'bca-toolbar__logo-link']) ?>
-			<?php
-				# バージョンアップ画面
-				elseif (Configure::read('BcRequest.isUpdater')): ?>
+						'https://basercms.net/manuals/introductions/4.html',
+						['target' => '_blank', 'class' => 'bca-toolbar__logo-link']
+				) ?>
+						
+			<?php // バージョンアップ画面 ?>
+			<?php elseif (Configure::read('BcRequest.isUpdater')): ?>
 				<?php $this->BcBaser->link(
 						$this->BcBaser->getImg('admin/logo_icon.svg', ['alt' => '', 'width' => '24', 'height' => '21', 'class' => 'bca-toolbar__logo-symbol']) .
 						'<span class="bca-toolbar__logo-text">' . __d('baser', 'アップデートマニュアル') . '</span>', 
-                        'https://basercms.net/manuals/introductions/8.html', ['target' => '_blank', 'class' => 'bca-toolbar__logo-link']) ?>
-			<?php
-				# 通常
-				elseif (!empty($this->request->params['admin']) || ('/' . $this->request->url) == $loginUrl): ?>
+						'https://basercms.net/manuals/introductions/8.html',
+						['target' => '_blank', 'class' => 'bca-toolbar__logo-link']
+				) ?>
+						
+			<?php // 通常管理画面 ?>
+			<?php elseif (!empty($this->request->params['admin']) || ('/' . $this->request->url) == $loginUrl): ?>
 				<?php
 					$this->BcBaser->link(
 						$this->BcBaser->getImg('admin/logo_icon.svg', ['alt' => '', 'width' => '24', 'height' => '21', 'class' => 'bca-toolbar__logo-symbol'])
-							.'<span class="bca-toolbar__logo-text">'
-							.$this->BcBaser->siteConfig['formal_name']
-							.'</span>', '/'
+							. '<span class="bca-toolbar__logo-text">'
+							. h($this->BcBaser->siteConfig['formal_name'])
+							. '</span>', '/'
 						,
 						['class' => 'bca-toolbar__logo-link']
 					)
 				?>
-			<?php
-				else: ?>
-				<?php
-					# 管理画面にアクセス可能な権限がある場合
-					if (in_array('admin', $currentUserAuthPrefixes)): ?>
+				
+			<?php // 公開画面 ?>
+			<?php else: ?>
+				<?php // 管理画面にアクセス可能な権限がある場合 ?>
+				<?php if (in_array('admin', $currentUserAuthPrefixes)): ?>
 					<?php
 					$this->BcBaser->link(
 						$this->BcBaser->getImg('admin/logo_icon.svg', ['alt' => '', 'width' => '24', 'height' => '21', 'class' => 'bca-toolbar__logo-symbol'])
-							.'<span class="bca-toolbar__logo-text">'
-							.$this->BcBaser->siteConfig['formal_name']
-							.'</span>', ['plugin' => null, 'admin' => true, 'controller' => 'dashboard', 'action' => 'index']
+							. '<span class="bca-toolbar__logo-text">'
+							. h($this->BcBaser->siteConfig['formal_name'])
+							. '</span>', ['plugin' => null, 'admin' => true, 'controller' => 'dashboard', 'action' => 'index']
 						,
 						['class' => 'bca-toolbar__logo-link']
 					)
 					?>
-				<?php
-				# 管理画面にアクセス権限がない場合
-				else: ?>
-					<?php $this->BcBaser->link($authName, Configure::read('BcAuthPrefix.' . $currentPrefix . '.loginRedirect'), ['title' => $authName]) ?>
+				<?php // 管理画面にアクセス権限がない場合 ?>
+				<?php else: ?>
+					<?php $this->BcBaser->link(h($authName), Configure::read('BcAuthPrefix.' . $currentPrefix . '.loginRedirect'), ['title' => h($authName)]) ?>
 				<?php endif ?>
 			<?php endif ?>
 		</div>
@@ -112,14 +114,16 @@
 		<div id="UserMenu" class="bca-toolbar__users">
 			<ul class="clearfix">
 				<?php
-				# TODO: お気に入りを表示（サイドメニューとのイベント処理・同期・スタイルの調整を検討中）
-				# <li>
-				# <a href="javascript:void(0)" class="title"><?php echo __d('baser', 'お気に入り') ? ><img src="/theme/admin-third/img/admin/btn_dropdown.png" width="8" height="11" class="bc-btn"></a>
-				#	<div id="FavoriteArea" hidden>
-				#		<?php $this->BcBaser->element('favorite_menu') ? >
-				#		<?php $this->BcBaser->element('permission') ? >
-				#	</div>
-				#</li>
+				/**
+				 * TODO: お気に入りを表示（サイドメニューとのイベント処理・同期・スタイルの調整を検討中）
+				 * <li>
+				 * <a href="javascript:void(0)" class="title"><?php echo __d('baser', 'お気に入り') ? ><img src="/theme/admin-third/img/admin/btn_dropdown.png" width="8" height="11" class="bc-btn"></a>
+				 * 	<div id="FavoriteArea" hidden>
+				 * 		<?php $this->BcBaser->element('favorite_menu') ? >
+				 * 		<?php $this->BcBaser->element('permission') ? >
+				 * 	</div>
+				 * </li>
+				 */
 				?>
 				<li>
 					<?php if (!empty($user)): ?>
```
