# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4122_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4122_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 29-51 of the vulnerable file.

				'UploaderCategories' => [
					'title' => __d('baser', 'カテゴリ'), 
					'url' => ['admin' => true, 'plugin' => 'uploader', 'controller' => 'uploader_categories', 'action' => 'index'],
					'currentRegex' => '/\/uploader\/uploader_categories\/[^\/]+?/s'
				],
			]
		],
	],
];
// @deprecated 5.0.0 since 4.2.0 BcApp.adminNavigation の形式に変更
$config['BcApp.adminNavi.uploader'] = [
		'name'		=> __d('baser', 'アップローダープラグイン'),
		'contents'	=> [
			['name' => __d('baser', 'アップロードファイル一覧'),	'url' => ['admin' => true, 'plugin' => 'uploader', 'controller' => 'uploader_files', 'action' => 'index']],
			['name' => __d('baser', 'カテゴリ一覧'), 'url' => ['admin' => true, 'plugin' => 'uploader', 'controller' => 'uploader_categories', 'action' => 'index']],
			['name' => __d('baser', 'カテゴリ新規登録'), 'url' => ['admin' => true, 'plugin' => 'uploader', 'controller' => 'uploader_categories', 'action' => 'add']],
			['name' => __d('baser', '基本設定'), 'url' => ['admin' => true, 'plugin' => 'uploader', 'controller' => 'uploader_configs', 'action' => 'index']],
	]
];
$config['Uploader'] = [
		// システム管理者グループ以外のユーザーがアップロード可能なファイル（拡張子をカンマ区切りで指定する）
		'allowedExt' => 'gif,jpg,png,pdf,zip,doc,docx,xls,xlsx,ppt,pptx'
];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,10 @@
 	]
 ];
 $config['Uploader'] = [
+		// システム管理者によるアップロードでいかなる拡張子も許可する
+		'allowedAdmin' => false,
 		// システム管理者グループ以外のユーザーがアップロード可能なファイル（拡張子をカンマ区切りで指定する）
-		'allowedExt' => 'gif,jpg,png,pdf,zip,doc,docx,xls,xlsx,ppt,pptx'
+		'allowedExt' => 'gif,jpg,jpeg,png,ico,pdf,zip,doc,docx,xls,xlsx,ppt,pptx,txt',
+		// 'allowedExt' => 'mp4,mp3,mpg,mpeg,avi,wmv' // メディア例
+		// 'allowedExt' => 'fon,ttf,ttc' // フォント例
 ];
```
