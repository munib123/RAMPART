# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3745_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3745_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-37 of the vulnerable file.

<?php

$l = OC_L10N::get('gallery');
$root = !empty($_GET['root']) ? $_GET['root'] : '/';
?>
<style>
div.gallery_div {position:relative; display: inline-block; height: 152px; width: 150px; margin: 5px;}
div.miniature_border {position:absolute; height: 150px; -moz-transition-duration: 0.2s; -o-transition-duration:0.2s;  -webkit-transition-duration: .2s; background-position: 50%;}
div.line {display:inline-block; border: 0; width: auto; height: 160px}
div.gallery_div img{position:absolute; top: 1; left: 0; -moz-transition-duration: 0.3s; -o-transition-duration:0.3s; -webkit-transition-duration: 0.3s; height:150px; width: auto;}
div.gallery_div img.shrinker {width:80px !important;}
div.title { opacity: 0; text-align: center; vertical-align: middle; font-family: Arial; font-size: 12px; border: 0; position: absolute; text-overflow: ellipsis; bottom: 20px; left:5px; height:auto; padding: 5px; width: 140px; background-color: black; color: white; -webkit-transition: opacity 0.5s;  z-index:1000; border-radius: 7px}
div.visible { opacity: 0.8;}
</style>
<script type="text/javascript">

var root = "<?php echo $root; ?>";

function explode(element) {
	$('div', element).each(function(index, elem) {
	 	if ($(elem).hasClass('title')) {
		 	$(elem).addClass('visible');
	 	} else {
			$(elem).css('margin-top', Math.floor(30-(Math.random()*60)) + 'px')
			       .css('margin-left', Math.floor(30-(Math.random()*60))+ 'px')
			       .css('z-index', '999');
		}
	});
}

function deplode(element) {
	$('div', element).each(function(index, elem) {
	 	if ($(elem).hasClass('title')) {
		 	$(elem).removeClass('visible');
	 	} else {
			$(elem).css('margin-top', Math.floor(5-(Math.random()*10)) + 'px')
		    	   .css('margin-left', Math.floor(5-(Math.random()*10))+ 'px')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,7 +14,7 @@
 </style>
 <script type="text/javascript">
 
-var root = "<?php echo $root; ?>";
+var root = "<?php echo htmlentities($root); ?>";
 
 function explode(element) {
 	$('div', element).each(function(index, elem) {
```
