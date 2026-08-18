# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4895_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4895_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 45-85 of the vulnerable file.

		exit;
	} else { // 送信失敗
		$_SESSION = array();  // セッションに格納された情報をカラにします。
		header("Location: error.php");
		exit;
	}
}

// ヘッダー表示
getHeader();
?>

<h1 class="page-header">お問い合わせ内容の確認</h1>

<div class="page-content">
	<p class="mb30">
		この内容でよろしければ送信するボタンを押してください。<br>
		メールアドレスに間違いがあると回答の返信ができませんので十分にご確認ください。
	</p>

	<form class="form-horizontal" name="contactform" role="form" method="post" action="<?php echo $_SERVER["PHP_SELF"]; ?>">
		<table class="table table-bordered confirm">
			<tr>
				<th>お名前</th>
				<td><?php echo htmlspchar($name); ?></td>
			</tr>
			<tr>
				<th>メールアドレス</th>
				<td><?php echo htmlspchar($email); ?></td>
			</tr>
			<tr>
				<th>お問い合わせ内容</th>
				<td><?php echo nl2br(htmlspchar($message)); ?></td>
			</tr>
		</table>

		<div class="btn-area">
			<button type="button" class="btn btn-default" onclick="contactform.action='index.php';contactform.submit();">戻る<i class="fa fa-reply"></i></button>
			<button type="submit" class="btn btn-success">送信する<i class="fa fa-envelope-o"></i></button>
			<input type="hidden" name="act" value="3">
		</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,7 +62,7 @@
 		メールアドレスに間違いがあると回答の返信ができませんので十分にご確認ください。
 	</p>
 
-	<form class="form-horizontal" name="contactform" role="form" method="post" action="<?php echo $_SERVER["PHP_SELF"]; ?>">
+	<form class="form-horizontal" name="contactform" role="form" method="post" action="<?php echo htmlspchar($_SERVER['PHP_SELF']); ?>">
 		<table class="table table-bordered confirm">
 			<tr>
 				<th>お名前</th>
```
