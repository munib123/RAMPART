# CrossVul Fix Pair: Incorrect Regular Expression in javascript
**Pair ID:** 529_0
**Vulnerability Class:** Incorrect Regular Expression
**CWE:** CWE-185
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `529_0`)

## Vulnerability Information & PoC

## Description
Incorrect Regular Expression - When the regular expression is used in protection mechanisms such as filtering or validation, this may allow an attacker to bypass the intended restrictions on the incoming data.

## Vulnerable Code
```javascript
Lines 2331-2373 of the vulnerable file.

		"'": '&#39;', // eslint-disable-line quotes
		'"': '&quot;'
	},

	/**
	 * Parse a simple HTML string into SVG tspans. Called internally when text
	 *   is set on an SVGElement. The function supports a subset of HTML tags,
	 *   CSS text features like `width`, `text-overflow`, `white-space`, and
	 *   also attributes like `href` and `style`.
	 * @private
	 * @param {SVGElement} wrapper The parent SVGElement.
	 */
	buildText: function (wrapper) {
		var textNode = wrapper.element,
			renderer = this,
			forExport = renderer.forExport,
			textStr = pick(wrapper.textStr, '').toString(),
			hasMarkup = textStr.indexOf('<') !== -1,
			lines,
			childNodes = textNode.childNodes,
			clsRegex,
			styleRegex,
			hrefRegex,
			wasTooLong,
			parentX = attr(textNode, 'x'),
			textStyles = wrapper.styles,
			width = wrapper.textWidth,
			textLineHeight = textStyles && textStyles.lineHeight,
			textOutline = textStyles && textStyles.textOutline,
			ellipsis = textStyles && textStyles.textOverflow === 'ellipsis',
			noWrap = textStyles && textStyles.whiteSpace === 'nowrap',
			fontSize = textStyles && textStyles.fontSize,
			textCache,
			isSubsequentLine,
			i = childNodes.length,
			tempParent = width && !wrapper.added && this.box,
			getLineHeight = function (tspan) {
				var fontSizeStyle;
				/*= if (build.classic) { =*/
				fontSizeStyle = /(px|em)$/.test(tspan && tspan.style.fontSize) ?
					tspan.style.fontSize :
					(fontSize || renderer.style.fontSize || 12);
				/*= } =*/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2348,9 +2348,6 @@
 			hasMarkup = textStr.indexOf('<') !== -1,
 			lines,
 			childNodes = textNode.childNodes,
-			clsRegex,
-			styleRegex,
-			hrefRegex,
 			wasTooLong,
 			parentX = attr(textNode, 'x'),
 			textStyles = wrapper.styles,
@@ -2390,6 +2387,23 @@
 					}
 				});
 				return inputStr;
+			},
+			parseAttribute = function (s, attr) {
+				var start,
+					delimiter;
+
+				start = s.indexOf('<');
+				s = s.substring(start, s.indexOf('>') - start);
+
+				start = s.indexOf(attr + '=');
+				if (start !== -1) {
+					start = start + attr.length + 1;
+					delimiter = s.charAt(start);
+					if (delimiter === '"' || delimiter === "'") { // eslint-disable-line quotes
+						s = s.substring(start + 1);
+						return s.substring(0, s.indexOf(delimiter));
+					}
+				}
 			};
 
 		// The buildText code is quite heavy, so if we're not changing something
@@ -2426,10 +2440,6 @@
 
 		// Complex strings, add more logic
 		} else {
-
-			clsRegex = /<.*class="([^"]+)".*>/;
-			styleRegex = /<.*style="([^"]+)".*>/;
-			hrefRegex = /<.*href="([^"]+)".*>/;
 
 			if (tempParent) {
 				// attach it to the DOM to read offset width
@@ -2485,27 +2495,31 @@
 								renderer.SVG_NS,
 								'tspan'
 							),
-							spanCls,
-							spanStyle; // #390
-						if (clsRegex.test(span)) {
-							spanCls = span.match(clsRegex)[1];
-							attr(tspan, 'class', spanCls);
+							classAttribute,
+							styleAttribute, // #390
+							hrefAttribute;
+						
+						classAttribute = parseAttribute(span, 'class');
+						if (classAttribute) {
+							attr(tspan, 'class', classAttribute);
 						}
-						if (styleRegex.test(span)) {
-							spanStyle = span.match(styleRegex)[1].replace(
+
+						styleAttribute = parseAttribute(span, 'style');
+						if (styleAttribute) {
+							styleAttribute = styleAttribute.replace(
 								/(;| |^)color([ :])/,
 								'$1fill$2'
 							);
-							attr(tspan, 'style', spanStyle);
+							attr(tspan, 'style', styleAttribute);
 						}
 
 						// Not for export - #1529
-						if (hrefRegex.test(span) && !forExport) {
+						hrefAttribute = parseAttribute(span, 'href');
+						if (hrefAttribute && !forExport) {
 							attr(
 								tspan,
 								'onclick',
-								'location.href=\"' +
-									span.match(hrefRegex)[1] + '\"'
+								'location.href=\"' + hrefAttribute + '\"'
 							);
 							attr(tspan, 'class', 'highcharts-anchor');
 							/*= if (build.classic) { =*/
@@ -2649,8 +2663,12 @@
 												dy: dy,
 												x: parentX
 											});
-											if (spanStyle) { // #390
-												attr(tspan, 'style', spanStyle);
+											if (styleAttribute) { // #390
+												attr(
+													tspan,
+													'style',
+													styleAttribute
+												);
 											}
 											textNode.appendChild(tspan);
 										}
```
