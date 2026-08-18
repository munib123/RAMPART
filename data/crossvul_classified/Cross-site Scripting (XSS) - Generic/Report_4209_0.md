# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4209_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4209_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 8-38 of the vulnerable file.

 * @package			Baser.View
 * @since			baserCMS v 4.4.0
 * @license			https://basercms.net/license/index.html
 */

/**
 * ブログコメント
 * 呼出箇所：ブログ記事詳細
 *
 * @var BcAppView $this
 * @var array $dbData コメントデータ
 */
?>


<?php if (!empty($dbData)): ?>
	<?php if ($dbData['status']): ?>
<div class="bs-blog-comment__list-item" id="Comment<?php echo $dbData['no'] ?>">
	<div class="bs-blog-comment__list-item-name">
		<?php if ($dbData['url']): ?>
			<?php $this->BcBaser->link($dbData['name'], $dbData['url'], ['target' => '_blank']) ?>
		<?php else: ?>
			<?php echo $dbData['name'] ?>
		<?php endif ?>
	</div>
	<div class="bs-blog-comment__list-item-message">
		<?php echo nl2br($this->BcText->autoLinkUrls($dbData['message'])) ?>
	</div>
</div>
	<?php endif ?>
<?php endif ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,9 +25,9 @@
 <div class="bs-blog-comment__list-item" id="Comment<?php echo $dbData['no'] ?>">
 	<div class="bs-blog-comment__list-item-name">
 		<?php if ($dbData['url']): ?>
-			<?php $this->BcBaser->link($dbData['name'], $dbData['url'], ['target' => '_blank']) ?>
+			<?php $this->BcBaser->link($dbData['name'], $dbData['url'], ['target' => '_blank', 'escape' => true]) ?>
 		<?php else: ?>
-			<?php echo $dbData['name'] ?>
+			<?php echo h($dbData['name']) ?>
 		<?php endif ?>
 	</div>
 	<div class="bs-blog-comment__list-item-message">
```
