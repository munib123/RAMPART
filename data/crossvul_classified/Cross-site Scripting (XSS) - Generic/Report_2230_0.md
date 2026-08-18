# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2230_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2230_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-27 of the vulnerable file.

<?php defined('SYSPATH') OR die('No direct access allowed.'); ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<?php if(isset ( $_SERVER['REQUEST_URI'])):?> 
<meta http-equiv="refresh" content="60; url=<?php echo $_SERVER['REQUEST_URI'] ?>">
<?php endif ?>
<title><?php echo $error ?></title>
<?php echo html::stylesheet('media/css/common.css') ?>
<?php echo html::stylesheet('media/css/ui-'.Kohana::config('core.theme').'/jquery-ui.css') ?>
<?php echo html::link('media/images/favicon.ico','icon','image/ico') ?>
<?php echo html::script('media/js/jquery-min.js')?>
<?php echo html::script('media/js/jquery-ui.min.js')?>
<style type="text/css">
<?php #include Kohana::find_file('views', 'kohana_errors', FALSE, 'css') ?>
</style>
</head>
<body>
<div class="pagebody">
<table class="body">
<tr valign="top"><td>
<div class="left ui-widget">
<div class="p2 ui-widget-header ui-corner-top">
<?php echo "PNP4Nagios Version ".PNP_VERSION ?>
</div>
<div class="p4 ui-widget-content ui-corner-bottom" style="width: 640px">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
 <head>
 <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
 <?php if(isset ( $_SERVER['REQUEST_URI'])):?> 
-<meta http-equiv="refresh" content="60; url=<?php echo $_SERVER['REQUEST_URI'] ?>">
+<meta http-equiv="refresh" content="60">
 <?php endif ?>
 <title><?php echo $error ?></title>
 <?php echo html::stylesheet('media/css/common.css') ?>
```
