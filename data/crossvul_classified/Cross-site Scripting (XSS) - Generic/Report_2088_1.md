# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2088_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2088_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1-17 of the vulnerable file.

<?php defined('SYSPATH') or die('No direct script access.');?>

	
<div class="well">
  	<div class="hero-unit">
   
		<h2>Page Not Found</h2>
	    <p>The requested page <?php echo HTML::anchor($requested_page, $requested_page) ?> is not found.</p>
	 
	    <p>It is either not existing, moved or deleted. Make sure the URL is correct. </p>
	     
	    <p>To go back to the previous page, click the Back button.</p>
	     
	    <p><a href="<?php echo URL::site('/', TRUE) ?>">If you wanted to go to the main page instead, click here.</a></p>
	  
  	</div>
</div><!--/well--> 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,17 +1,17 @@
 <?php defined('SYSPATH') or die('No direct script access.');?>
 
-	
+    
 <div class="well">
-  	<div class="hero-unit">
+    <div class="hero-unit">
    
-		<h2>Page Not Found</h2>
-	    <p>The requested page <?php echo HTML::anchor($requested_page, $requested_page) ?> is not found.</p>
-	 
-	    <p>It is either not existing, moved or deleted. Make sure the URL is correct. </p>
-	     
-	    <p>To go back to the previous page, click the Back button.</p>
-	     
-	    <p><a href="<?php echo URL::site('/', TRUE) ?>">If you wanted to go to the main page instead, click here.</a></p>
-	  
-  	</div>
+        <h2><?=__('Page Not Found')?></h2>
+        <p><?=__('The requested page')?> <?php echo HTML::anchor($requested_page, $requested_page) ?> <?=__('is not found')?>.</p>
+     
+        <p><?=__('It is either not existing, moved or deleted. Make sure the URL is correct.')?> </p>
+         
+        <p><?=__('To go back to the previous page, click the Back button.')?></p>
+         
+        <p><a href="<?php echo URL::site('/', TRUE) ?>"><?=__('If you wanted to go to the main page instead, click here.')?></a></p>
+      
+    </div>
 </div><!--/well--> 
```
