# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4206_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4206_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 57-97 of the vulnerable file.

/**
 * ThemeFilesController constructor.
 *
 * @param CakeRequest $request
 * @param CakeResponse $response
 */
	public function __construct(CakeRequest $request, CakeResponse $response) {
		parent::__construct($request, $response);
		$this->_tempalteTypes = [
			'Layouts'	=> __d('baser', 'レイアウトテンプレート'),
			'Elements'	=> __d('baser', 'エレメントテンプレート'),
			'Emails'	=> __d('baser', 'Eメールテンプレート'),
			'etc'		=> __d('baser', 'コンテンツテンプレート'),
			'css'		=> __d('baser', 'スタイルシート'),
			'js'		=> 'Javascript',
			'img'		=> __d('baser', 'イメージ')
		];
		$this->crumbs = [
			['name' => __d('baser', 'テーマ管理'), 'url' => ['admin' => true, 'controller' => 'themes', 'action' => 'index']]
		];
	}

	/**
 * テーマファイル一覧
 *
 * @return void
 */
	public function admin_index() {
		$args = $this->_parseArgs(func_get_args());
		extract($args);

		if (!$theme) {
			$this->notFound();
		}

		// タイトル設定
		$pageTitle = $theme;
		if ($plugin) {
			$pageTitle .= '：' . $plugin;
		}
		$this->pageTitle = $pageTitle;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -74,6 +74,24 @@
 		$this->crumbs = [
 			['name' => __d('baser', 'テーマ管理'), 'url' => ['admin' => true, 'controller' => 'themes', 'action' => 'index']]
 		];
+
+		// テーマ編集機能が制限されている場合はアクセス禁止
+		if (Configure::read('BcApp.allowedThemeEdit') == false) {
+			$denyList = [
+				'admin_index',
+				'admin_add',
+				'admin_edit',
+				'admin_add_folder',
+				'admin_edit_folder',
+			];
+			// coreのindexはアクセス可能
+			if ($this->request->params['pass'][0] === 'core') {
+				unset($denyList[array_search('admin_index', $denyList)]);
+			}
+			if (in_array($this->request->action, $denyList)) {
+				$this->notfound();
+			}
+		}
 	}
 
 	/**
@@ -136,13 +154,13 @@
 			$excludeFileList = ['screenshot.png', 'VERSION.txt', 'config.php', 'AppView.php', 'BcAppView.php'];
 			if (!$path) {
 				$excludeFolderList = [
-					'Layouts', 
-					'Elements', 
+					'Layouts',
+					'Elements',
 					'Emails',
-					'Helper', 
+					'Helper',
 					'Config',
-					'Plugin',					
-					'img', 
+					'Plugin',
+					'img',
 					'css',
 					'js',
 					'_notes'
@@ -185,9 +203,9 @@
 
 /**
  * ファイルタイプを取得する
- * 
+ *
  * @param string $file
- * @return mixed false / type 
+ * @return mixed false / type
  */
 	protected function _getFileType($file) {
 		if (preg_match('/^(.+?)(\.ctp|\.php|\.css|\.js)$/is', $file)) {
@@ -873,7 +891,7 @@
 /**
  * 画像を表示する
  * コアの画像等も表示可
- * 
+ *
  * @param array パス情報
  * @return void
  */
@@ -901,7 +919,7 @@
 /**
  * 画像を表示する
  * コアの画像等も表示可
- * 
+ *
  * @param int $width
  * @param int $height
  * @param array パス情報
```
