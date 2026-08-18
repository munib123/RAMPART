# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2821_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2821_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 89-129 of the vulnerable file.

			// tooltip does fit neither above nor below: put him vertical centered left or right of cursor
			if (space_left.bottom < tooltip_height && space_left.top < tooltip_height) {
				if (tooltip_height > window_height-20) {
					tooltip_div.css('max-height', tooltip_height=window_height-20);
				}
				tooltip_div.css('top', (window_height-tooltip_height)/2);
			} else if (space_left.bottom < tooltip_height) {
				tooltip_div.css('top', cursor_rect.top - tooltip_height);
			} else {
				tooltip_div.css('top', cursor_rect.bottom);
			}

			tooltip_div.fadeIn(100);
		}
	}

	/**
	 * Creates the tooltip_div with the given text.
	 *
	 * @param {string} _html
	 */
	function prepare(_html)
	{
		// Free and null the old tooltip_div
		hide();

		//Generate the tooltip div, set it's text and append it to the body tag
		tooltip_div = jQuery(_wnd.document.createElement('div'));
		tooltip_div.hide();
		tooltip_div.append(_html);
		tooltip_div.addClass("egw_tooltip");
		jQuery(_wnd.document.body).append(tooltip_div);

		//The tooltip should automatically hide when the mouse comes over it
		tooltip_div.mouseenter(function() {
				hide();
		});
	}

	/**
	 * showTooltipTimeout is used to prepare showing the tooltip.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -106,8 +106,9 @@
 	 * Creates the tooltip_div with the given text.
 	 *
 	 * @param {string} _html
-	 */
-	function prepare(_html)
+	 * @param {boolean} _isHtml if set to true content gets appended as html
+	 */
+	function prepare(_html, _isHtml)
 	{
 		// Free and null the old tooltip_div
 		hide();
@@ -115,7 +116,14 @@
 		//Generate the tooltip div, set it's text and append it to the body tag
 		tooltip_div = jQuery(_wnd.document.createElement('div'));
 		tooltip_div.hide();
-		tooltip_div.append(_html);
+		if (_isHtml)
+		{
+			tooltip_div.append(_html);
+		}
+		else
+		{
+			tooltip_div.text(_html)
+		}
 		tooltip_div.addClass("egw_tooltip");
 		jQuery(_wnd.document.body).append(tooltip_div);
 
@@ -156,14 +164,14 @@
 		 * 	has to be a jQuery node.
 		 * @param _html is the html code which should be shown as tooltip.
 		 */
-		tooltipBind: function(_elem, _html) {
+		tooltipBind: function(_elem, _html, _isHtml) {
 			if (_html != '')
 			{
 				_elem.bind('mouseenter.tooltip', function(e) {
 					if (_elem != current_elem)
 					{
 						//Prepare the tooltip
-						prepare(_html);
+						prepare(_html, _isHtml);
 
 						// Set the current element the mouse is over and
 						// initialize the position variables
```
