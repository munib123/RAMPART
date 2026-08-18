# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4206_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4206_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 159-199 of the vulnerable file.

				['name' => __d('baser', 'ユーティリティ'), 'url' => ['admin' => true, 'plugin' => null, 'controller' => 'tools', 'action' => 'index']],
				['name' => __d('baser', 'サーバーキャッシュ削除'), 'url' => ['admin' => true, 'plugin' => null, 'controller' => 'site_configs', 'action' => 'del_cache'], 'options' => ['confirm' => __d('baser', 'サーバーキャッシュを削除します。いいですか？')]]
	]]],
	// コアプラグイン
	'corePlugins' => ['Blog', 'Feed', 'Mail', 'Uploader'],
	// アップデートキー
	'updateKey' => 'update',
	// 管理者グループID
	'adminGroupId' => 1,
	// エディター
	'editors' => [
		'none' => __d('baser', 'なし'),
		'BcCkeditor' => 'CKEditor'
	],
	'testTheme' => 'bc_sample',
	// 固定ページでシンタックスエラーチェックを行うかどうか
	// お名前ドットコムの場合、CLI版PHPの存在確認の段階で固まってしまう
	'validSyntaxWithPage' => true,
	// 管理者以外のPHPコードを許可するかどうか
	'allowedPhpOtherThanAdmins' => true,
	'marketThemeRss' => 'https://market.basercms.net/themes.rss',
	'marketPluginRss' => 'https://market.basercms.net/plugins.rss',
	'specialThanks'	=> 'https://basercms.net/special_thanks/special_thanks/ajax_users',
	// 管理システムのデフォルトテーマ
	'defaultAdminTheme' => 'admin-third',
	// コンテンツの作成日を自動で更新する
	'autoUpdateContentCreatedDate' => true,
	// オートプレフィックス除外設定（絶対URL）
	// 「すべてのリンクをサブサイト用に変換する」指定時、全てのリンクに対してプレフィックスを備える箇所に除外指定できる
	// 指定した絶対URLを記載しているリンクは変換しない
	// 例: 'https://basercms.net/'と記載 → https://basercms.net/s/ は s が付かなくなる
	'excludeAbsoluteUrlAddPrefix' => [],
	// オートプレフィックス除外設定（ディレクトリ）
	// 指定したディレクトリURLを記載しているリンクは変換しない
	// 例: 'test/' と記載 → https://basercms.net/s/test/ は s が付かなくなる
	'excludeListAddPrefix' => [],
	// generator のメタタグを出力するかどうか
	'outputMetaGenerator' => true,
	// 外部リンク
	'outerLinks' => [
		// インストールマニュアル
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,6 +176,8 @@
 	'validSyntaxWithPage' => true,
 	// 管理者以外のPHPコードを許可するかどうか
 	'allowedPhpOtherThanAdmins' => true,
+	// テーマ編集機能の利用を許可するかどうか
+	'allowedThemeEdit' => false,
 	'marketThemeRss' => 'https://market.basercms.net/themes.rss',
 	'marketPluginRss' => 'https://market.basercms.net/plugins.rss',
 	'specialThanks'	=> 'https://basercms.net/special_thanks/special_thanks/ajax_users',
```
