# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 904_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `904_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 187-227 of the vulnerable file.

	{
		editorUi.hideDialog();
		
		if (cancelFn != null)
		{
			cancelFn();
		}
	});
	cancelBtn.className = 'geBtn';

	if (editorUi.editor.cancelFirst)
	{
		buttons.appendChild(cancelBtn);
	}
	
	var applyFunction = (apply != null) ? apply : this.createApplyFunction();
	
	var applyBtn = mxUtils.button(mxResources.get('apply'), function()
	{
		var color = input.value;
		ColorDialog.addRecentColor(color, 12);
		
		if (color != 'none' && color.charAt(0) != '#')
		{
			color = '#' + color;
		}

		applyFunction(color);
		editorUi.hideDialog();
	});
	applyBtn.className = 'geBtn gePrimaryBtn';
	buttons.appendChild(applyBtn);
	
	if (!editorUi.editor.cancelFirst)
	{
		buttons.appendChild(cancelBtn);
	}
	
	if (color != null)
	{
		if (color == 'none')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,14 +204,21 @@
 	var applyBtn = mxUtils.button(mxResources.get('apply'), function()
 	{
 		var color = input.value;
-		ColorDialog.addRecentColor(color, 12);
-		
-		if (color != 'none' && color.charAt(0) != '#')
-		{
-			color = '#' + color;
-		}
-
-		applyFunction(color);
+		// https://stackoverflow.com/questions/8027423/how-to-check-if-a-string-is-a-valid-hex-color-representation/8027444
+		var colorValid  = /(^#?[0-9A-F]{6}$)|(^#[0-9A-F]{3}$)/i.test(color);
+		
+		if (colorValid)
+		{
+			ColorDialog.addRecentColor(color, 12);
+			
+			if (color != 'none' && color.charAt(0) != '#')
+			{
+				color = '#' + color;
+			}
+
+			applyFunction(color);			
+		}
+
 		editorUi.hideDialog();
 	});
 	applyBtn.className = 'geBtn gePrimaryBtn';
```
