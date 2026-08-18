# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4529_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4529_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 55-95 of the vulnerable file.

endif;
?>
		<script type="text/javascript" data-cfasync="false" src="js/zlib-1.2.11.js" integrity="sha512-Yey/0yoaVmSbqMEyyff3DIu8kCPwpHvHf7tY1AuZ1lrX9NPCMg87PwzngMi+VNbe4ilCApmePeuKT869RTcyCQ==" crossorigin="anonymous"></script>
		<script type="text/javascript" data-cfasync="false" src="js/base-x-3.0.5.1.js" integrity="sha512-/zL3MWKMtl1IBF0URx3laql2jUw+rWfFFabNlILY/Qm+hUsQR/XULjUyNHkW/FkrV7A0sMQ7tsppH7sj5ht8wA==" crossorigin="anonymous"></script>
		<script type="text/javascript" data-cfasync="false" src="js/rawinflate-0.3.js" integrity="sha512-g8uelGgJW9A/Z1tB6Izxab++oj5kdD7B4qC7DHwZkB6DGMXKyzx7v5mvap2HXueI2IIn08YlRYM56jwWdm2ucQ==" crossorigin="anonymous"></script>
		<script type="text/javascript" data-cfasync="false" src="js/bootstrap-3.3.7.js" integrity="sha512-iztkobsvnjKfAtTNdHkGVjAYTrrtlC7mGp/54c40wowO7LhURYl3gVzzcEqGl/qKXQltJ2HwMrdLcNUdo+N/RQ==" crossorigin="anonymous"></script>
<?php
if ($SYNTAXHIGHLIGHTING):
?>
		<script type="text/javascript" data-cfasync="false" src="js/prettify.js?<?php echo rawurlencode($VERSION); ?>" integrity="sha512-puO0Ogy++IoA2Pb9IjSxV1n4+kQkKXYAEUtVzfZpQepyDPyXk8hokiYDS7ybMogYlyyEIwMLpZqVhCkARQWLMg==" crossorigin="anonymous"></script>
<?php
endif;
if ($MARKDOWN):
?>
		<script type="text/javascript" data-cfasync="false" src="js/showdown-1.9.1.js" integrity="sha512-VeINC2WUWLyxgeQ56SsYFjQ5+d7RLvLPYOEYDFtEDd3AyVsgIsHYsWZ6WwgALwB6YR6qrVEM3IH4Bck96IfbMw==" crossorigin="anonymous"></script>
<?php
endif;
?>
		<script type="text/javascript" data-cfasync="false" src="js/purify-2.0.7.js" integrity="sha512-XjNEK1xwh7SJ/7FouwV4VZcGW9cMySL3SwNpXgrURLBcXXQYtZdqhGoNdEwx9vwLvFjUGDQVNgpOrTsXlSTiQg==" crossorigin="anonymous"></script>
		<script type="text/javascript" data-cfasync="false" src="js/legacy.js?<?php echo rawurlencode($VERSION); ?>" integrity="sha512-LYos+qXHIRqFf5ZPNphvtTB0cgzHUizu2wwcOwcwz/VIpRv9lpcBgPYz4uq6jx0INwCAj6Fbnl5HoKiLufS2jg==" crossorigin="anonymous"></script>
		<script type="text/javascript" data-cfasync="false" src="js/privatebin.js?<?php echo rawurlencode($VERSION); ?>" integrity="sha512-Bppv5Tt3fBwlJMQaL3ktLhrCNKZQwWo9ox4A/CAXiUs3rQLjfPSuEVViyuYy11e9oOaTKrMb7ejrkwDjhK1NmA==" crossorigin="anonymous"></script>
		<link rel="apple-touch-icon" href="img/apple-touch-icon.png?<?php echo rawurlencode($VERSION); ?>" sizes="180x180" />
		<link rel="icon" type="image/png" href="img/favicon-32x32.png?<?php echo rawurlencode($VERSION); ?>" sizes="32x32" />
		<link rel="icon" type="image/png" href="img/favicon-16x16.png?<?php echo rawurlencode($VERSION); ?>" sizes="16x16" />
		<link rel="manifest" href="manifest.json?<?php echo rawurlencode($VERSION); ?>" />
		<link rel="mask-icon" href="img/safari-pinned-tab.svg?<?php echo rawurlencode($VERSION); ?>" color="#ffcc00" />
		<link rel="shortcut icon" href="img/favicon.ico">
		<meta name="msapplication-config" content="browserconfig.xml">
		<meta name="theme-color" content="#ffe57e" />
	</head>
	<body role="document" data-compression="<?php echo rawurlencode($COMPRESSION); ?>"<?php
$class = array();
if ($isCpct) {
    $class[] = 'navbar-spacing';
}
if ($isDark) {
    $class[] = 'dark-theme';
}
if (count($class)) {
    echo ' class="', implode(' ', $class), '"';
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,7 @@
 ?>
 		<script type="text/javascript" data-cfasync="false" src="js/purify-2.0.7.js" integrity="sha512-XjNEK1xwh7SJ/7FouwV4VZcGW9cMySL3SwNpXgrURLBcXXQYtZdqhGoNdEwx9vwLvFjUGDQVNgpOrTsXlSTiQg==" crossorigin="anonymous"></script>
 		<script type="text/javascript" data-cfasync="false" src="js/legacy.js?<?php echo rawurlencode($VERSION); ?>" integrity="sha512-LYos+qXHIRqFf5ZPNphvtTB0cgzHUizu2wwcOwcwz/VIpRv9lpcBgPYz4uq6jx0INwCAj6Fbnl5HoKiLufS2jg==" crossorigin="anonymous"></script>
-		<script type="text/javascript" data-cfasync="false" src="js/privatebin.js?<?php echo rawurlencode($VERSION); ?>" integrity="sha512-Bppv5Tt3fBwlJMQaL3ktLhrCNKZQwWo9ox4A/CAXiUs3rQLjfPSuEVViyuYy11e9oOaTKrMb7ejrkwDjhK1NmA==" crossorigin="anonymous"></script>
+		<script type="text/javascript" data-cfasync="false" src="js/privatebin.js?<?php echo rawurlencode($VERSION); ?>" integrity="sha512-HxU8g6MFviBCv6fEKEL+bn0fICxg9++ZUxxqySWXkX4iGgLodH/OVZDfr3dgKK5vZAv+0niWLuf+CWZ+/gUwWw==" crossorigin="anonymous"></script>
 		<link rel="apple-touch-icon" href="img/apple-touch-icon.png?<?php echo rawurlencode($VERSION); ?>" sizes="180x180" />
 		<link rel="icon" type="image/png" href="img/favicon-32x32.png?<?php echo rawurlencode($VERSION); ?>" sizes="32x32" />
 		<link rel="icon" type="image/png" href="img/favicon-16x16.png?<?php echo rawurlencode($VERSION); ?>" sizes="16x16" />
```
