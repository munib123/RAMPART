# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4209_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4209_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php $this->BcBaser->js('admin/libs/jquery.baseUrl.js', false, ['once' => true]); ?>
<?php $this->BcBaser->js('admin/libs/jquery.bcUtil.js', false, ['once' => true]); ?>
<?php $this->BcBaser->js('admin/libs/jquery.bcToken.js', false, ['once' => true]); ?>
<?php $this->BcBaser->js('Blog.blog_comments_scripts.js', false, [
	'once' => true,
	'id' => 'BlogCommentsScripts',
	'data-alertMessageName' => __('お名前を入力してください'),
	'data-alertMessageComment' => __('コメントを入力してください'),
	'data-alertMessageAuthImage' => __('画像の文字を入力してください'),
	'data-alertMessageAuthComplate' => __('送信が完了しました。送信された内容は確認後公開させて頂きます。'),
	'data-alertMessageComplate' => __('コメントの送信が完了しました。'),
	'data-alertMessageError' => __('コメントの送信に失敗しました。入力内容を見なおしてください。'),
]); ?>
<div id="BaseUrl" style="display: none"><?php echo $this->request->base; ?></div>

<script>
	authCaptcha = <?php echo $blogContent['BlogContent']['auth_captcha'] ? 'true' : 'false'; ?>;
	commentApprove = <?php echo $blogContent['BlogContent']['comment_approve'] ? 'true' : 'false'; ?>;

	$(function() {
		loadAuthCaptcha();
		$("#BlogCommentAddButton").click(function() {
			sendComment();
			return false;
		});
	});
</script>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -11,7 +11,7 @@
 	'data-alertMessageComplate' => __('コメントの送信が完了しました。'),
 	'data-alertMessageError' => __('コメントの送信に失敗しました。入力内容を見なおしてください。'),
 ]); ?>
-<div id="BaseUrl" style="display: none"><?php echo $this->request->base; ?></div>
+<div id="BaseUrl" style="display: none"><?php echo h($this->request->base); ?></div>
 
 <script>
 	authCaptcha = <?php echo $blogContent['BlogContent']['auth_captcha'] ? 'true' : 'false'; ?>;
```
