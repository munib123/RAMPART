# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 877_12
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `877_12`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 71-111 of the vulnerable file.


		// Include add content to the editor
		$html .= 'function addContentSimpleMDE(content) {
				var text = simplemde.value();
				simplemde.value(text + content + "\n");
				simplemde.codemirror.refresh();
			}'.PHP_EOL;

		// Returns the content of the editor
		// Function required for Bludit
		$html .= 'function editorGetContent(content) {
			return simplemde.value();
		}'.PHP_EOL;

		// Insert an image in the editor at the cursor position
		// Function required for Bludit
		$html .= 'function editorInsertMedia(filename) {
				addContentSimpleMDE("!['.$L->get('Image description').']("+filename+")");
			}'.PHP_EOL;

		$html .= '$(document).ready(function() { '.PHP_EOL;
		$html .= 'simplemde = new SimpleMDE({
				element: document.getElementById("jseditor"),
				status: false,
				toolbarTips: true,
				toolbarGuideIcon: true,
				autofocus: false,
				placeholder: "'.$L->get('content-here-supports-markdown-and-html-code').'",
				lineWrapping: true,
				autoDownloadFontAwesome: false,
				indentWithTabs: true,
				tabSize: '.$this->getValue('tabSize').',
				spellChecker: '.$spellCheckerEnable.',
				toolbar: ['.Sanitize::htmlDecode($this->getValue('toolbar')).',
					"|",
					{
					name: "pageBreak",
					action: function addPageBreak(editor){
						var cm = editor.codemirror;
						output = "\n'.PAGE_BREAK.'\n";
						cm.replaceSelection(output);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,7 +88,7 @@
 				addContentSimpleMDE("!['.$L->get('Image description').']("+filename+")");
 			}'.PHP_EOL;
 
-		$html .= '$(document).ready(function() { '.PHP_EOL;
+		//$html .= '$(document).ready(function() { '.PHP_EOL;
 		$html .= 'simplemde = new SimpleMDE({
 				element: document.getElementById("jseditor"),
 				status: false,
@@ -114,7 +114,7 @@
 					title: "'.$L->get('Pagebreak').'",
 					}]
 		});';
-		$html .= '}); </script>';
+		$html .= '</script>';
 		return $html;
 	}
 }
```
