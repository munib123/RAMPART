# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3162_5
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3162_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 6-46 of the vulnerable file.

# DEV NAME : Jean-Philippe LEVY
# VERSION : 5.0
# APPLICATION : eonweb for eyesofnetwork project
#
# LICENCE :
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#########################################
*/

# Check optionnal module to load
if(isset($_GET["module"]) && isset($_GET["link"])) { 

	$module=exec("rpm -q ".$_GET["module"]." |grep '.eon' |wc -l");
	
	# Redirect to module page if rpm installed
	if($module!=0) { header('Location: '.$_GET["link"].''); }

} 
	
include("../header.php"); 
include("../side.php"); 

?>

<div id="page-wrapper">

	<div class="row">
		<div class="col-lg-12">
			<h1 class="page-header"><?php echo getLabel("label.home_about.title"); ?></h1>
		</div>
	</div>

	<div class="row">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,10 +23,14 @@
 # Check optionnal module to load
 if(isset($_GET["module"]) && isset($_GET["link"])) { 
 
-	$module=exec("rpm -q ".$_GET["module"]." |grep '.eon' |wc -l");
+	include("../include/config.php");
+	include("../include/arrays.php");
 	
-	# Redirect to module page if rpm installed
-	if($module!=0) { header('Location: '.$_GET["link"].''); }
+	if(in_array($_GET["module"],$array_modules)) {
+		$module=exec("rpm -q ".$_GET["module"]." |grep '.eon' |wc -l");
+		# Redirect to module page if rpm installed
+		if($module!=0) { header('Location: '.$_GET["link"].''); }
+	}
 
 } 
 	
```
