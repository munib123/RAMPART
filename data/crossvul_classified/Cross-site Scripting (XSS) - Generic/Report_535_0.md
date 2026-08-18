# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 535_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `535_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 138-178 of the vulnerable file.


		echo '<div class="layout_links" style="float:right">';
		echo '<a href="#gp_new_copy" data-cmd="tabs" class="selected">'. $langmessage['Copy'] .'</a>';
		echo '<a href="#gp_new_type" data-cmd="tabs">'. $langmessage['Content Type'] .'</a>';
		echo '</div>';


		echo '<h3>'.$langmessage['new_file'].'</h3>';


		echo '<form action="'.$this->GetUrl('Admin/Menu/Ajax').'" method="post">';
		if( isset($_REQUEST['redir']) ){
			echo '<input type="hidden" name="redir" value="redir" />';
		}


		echo '<table class="bordered full_width">';
		echo '<tr><th colspan="2">'.$langmessage['options'].'</th></tr>';

		//title
		echo '<tr><td>';
		echo $langmessage['label'];
		echo '</td><td>';
		echo '<input type="text" name="title" maxlength="100" size="50" value="'.htmlspecialchars($_REQUEST['title']).'" class="gpinput full_width" required/>';
		echo '</td></tr>';

		//copy
		echo '<tbody id="gp_new_copy">';
		echo '<tr><td>';
		echo $langmessage['Copy'];
		echo '</td><td>';
		$gp_index_no_special = array();
		foreach( $gp_index as $title => $index ){
			if( strpos(strtolower($index),'special_') !== 0 ){
				$gp_index_no_special[$title] = $index;
			}
		}
		\gp\admin\Menu\Tools::ScrollList($gp_index_no_special);
		echo sprintf($format_bottom,'CopyPage',$langmessage['create_new_file']);


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,10 +155,13 @@
 		echo '<tr><th colspan="2">'.$langmessage['options'].'</th></tr>';
 
 		//title
+		$new_title = htmlspecialchars($_REQUEST['title']);
+		// prevent code injections
+		$new_title = str_replace(array('=', '/', '{', '}', ':', ',', ';'), '', $new_title);
 		echo '<tr><td>';
 		echo $langmessage['label'];
 		echo '</td><td>';
-		echo '<input type="text" name="title" maxlength="100" size="50" value="'.htmlspecialchars($_REQUEST['title']).'" class="gpinput full_width" required/>';
+		echo '<input type="text" name="title" maxlength="100" size="50" value="'. $new_title .'" class="gpinput full_width" required/>';
 		echo '</td></tr>';
 
 		//copy
```
