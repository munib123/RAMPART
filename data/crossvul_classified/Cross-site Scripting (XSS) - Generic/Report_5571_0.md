# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5571_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5571_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 434-474 of the vulnerable file.

			break;

			case 'text':
			default:
				$default_content = '<p>'.$langmessage['New Section'].'</p>';
			break;
		}

		$default_content = gpPlugin::Filter('GetDefaultContent',array($default_content,$type));

		return $default_content;
	}

	/**
	 * Display a form for adding a new section to the page
	 *
	 */
	function NewSectionPrompt(){
		global $langmessage;


		ob_start();
		echo '<div class="inline_box">';
		echo '<form method="post" action="'.common::GetUrl($this->title).'">';
		echo '<h2>'.$langmessage['new_section_about'].'</h2>';

		echo '<table class="bordered full_width">';
		echo '<tr><th colspan="2">'.$langmessage['New Section'].'</th></tr>';

		echo '<tr><td>';
		echo $langmessage['Content Type'];
		echo '</td><td>';
		editing_page::SectionTypes();
		echo '</td></tr>';

		echo '<tr><td>';
		echo $langmessage['Insert Location'];
		echo '</td><td>';
		echo '<label><input type="radio" name="insert" value="before" /> ';
		echo $langmessage['insert_before'];
		echo '</label>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -451,7 +451,6 @@
 	function NewSectionPrompt(){
 		global $langmessage;
 
-
 		ob_start();
 		echo '<div class="inline_box">';
 		echo '<form method="post" action="'.common::GetUrl($this->title).'">';
@@ -481,7 +480,7 @@
 
 		echo '<p>';
 		echo '<input type="hidden" name="last_mod" value="'.$this->fileModTime.'" />';
-		echo '<input type="hidden" name="section" value="'.$_GET['section'].'" />';
+		echo '<input type="hidden" name="section" value="'.htmlspecialchars($_GET['section']).'" />';
 		echo '<input type="hidden" name="cmd" value="add_section" />';
 		echo '<input type="submit" name="" value="'.$langmessage['save'].'" class="gpsubmit"/>';
 		echo ' <input type="button" name="" value="'.$langmessage['cancel'].'" class="admin_box_close gpcancel" />';
```
