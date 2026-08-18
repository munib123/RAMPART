# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4122_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4122_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 56-96 of the vulnerable file.

 *
 * @param	int		$id
 * @param	string	$table
 * @param	string	$ds
 */
	public function __construct($id = false, $table = null, $ds = null) {
		$this->validate = [
			'publish_begin' => [
				'checkPeriod' => [
					'rule' => 'checkPeriod',
					'message' => __d('baser', '公開期間が不正です。')
				]
			],
			'publish_end' => [
				'checkPeriod' => [
					'rule' => 'checkPeriod',
					'message' => __d('baser', '公開期間が不正です。')
				]
			]
		];
		if(!BcUtil::isAdminUser()) {
			$this->validate['name'] = [
				'fileExt' => [
					'rule' => ['fileExt', Configure::read('Uploader.allowedExt')],
					'message' => __d('baser', '許可されていないファイル形式です。')
				]
			];
		}
		parent::__construct($id, $table, $ds);
		$sizes = array('large', 'midium', 'small', 'mobile_large', 'mobile_small');
		$UploaderConfig = ClassRegistry::init('Uploader.UploaderConfig');
		$uploaderConfigs = $UploaderConfig->findExpanded();
		$imagecopy = array();
		
		foreach($sizes as $size) {
			if(!isset($uploaderConfigs[$size.'_width']) || !isset($uploaderConfigs[$size.'_height'])) {
				continue;
			}
			$imagecopy[$size] = array('suffix'	=> '__'.$size);
			$imagecopy[$size]['width'] = $uploaderConfigs[$size.'_width'];
			$imagecopy[$size]['height'] = $uploaderConfigs[$size.'_height'];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,7 +73,7 @@
 				]
 			]
 		];
-		if(!BcUtil::isAdminUser()) {
+		if(!BcUtil::isAdminUser() || !Configure::read('Uploader.allowedAdmin')) {
 			$this->validate['name'] = [
 				'fileExt' => [
 					'rule' => ['fileExt', Configure::read('Uploader.allowedExt')],
```
