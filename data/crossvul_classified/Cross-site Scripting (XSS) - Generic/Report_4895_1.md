# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4895_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4895_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 58-98 of the vulnerable file.


// ヘッダー表示
getHeader();
?>

<h1 class="page-header">お問い合わせ</h1>

<?php if (count($err_msg) > 0) { ?>
<div>
	<ul class="error">
		<?php foreach ($err_msg as $msg) { ?>
		<li><?php echo $msg; ?></li>
		<?php } ?>
	</ul>
</div>
<?php } ?>

<div class="page-content">
	<p class="mb30">以下を入力し確認するボタンを押してください。<span class="red">*</span>は入力必須です。</p>

	<form class="form-horizontal" name="contactform" role="form" method="post" action="<?php echo $_SERVER["PHP_SELF"]; ?>" novalidate>
		<div class="form-group">
			<label for="inputName" class="col-sm-3 control-label">お名前<span class="red">*</span></label>
			<div class="col-sm-9">
				<input type="text" class="form-control" name="contact_data[name]" placeholder="お名前" value="<?php echo htmlspchar($name); ?>">
			</div>
		</div>
		<div class="form-group">
			<label for="inputEmail" class="col-sm-3 control-label">メールアドレス<span class="red">*</span></label>
			<div class="col-sm-9">
				<input type="email" class="form-control" name="contact_data[email]" placeholder="メールアドレス" value="<?php echo htmlspchar($email); ?>">
			</div>
		</div>
		<div class="form-group">
			<label for="inputMessage" class="col-sm-3 control-label">お問い合わせ内容<span class="red">*</span></label>
			<div class="col-sm-9">
				<textarea class="form-control" name="contact_data[message]" rows="5"><?php echo htmlspchar($message); ?></textarea>
			</div>
		</div>
		<div class="btn-area">
			<button type="submit" name="btnSubmit" class="btn btn-success">確認する<i class="fa fa-arrow-circle-right"></i></button>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,7 +75,7 @@
 <div class="page-content">
 	<p class="mb30">以下を入力し確認するボタンを押してください。<span class="red">*</span>は入力必須です。</p>
 
-	<form class="form-horizontal" name="contactform" role="form" method="post" action="<?php echo $_SERVER["PHP_SELF"]; ?>" novalidate>
+	<form class="form-horizontal" name="contactform" role="form" method="post" action="<?php echo htmlspchar($_SERVER['PHP_SELF']); ?>" novalidate>
 		<div class="form-group">
 			<label for="inputName" class="col-sm-3 control-label">お名前<span class="red">*</span></label>
 			<div class="col-sm-9">
```
