# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 38_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `38_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 372-412 of the vulnerable file.

			}
			temp.push('</style>');

			output = temp.concat(output);
		}

		return output.join('');
	}

	render(body, style, options = null) {
		if (!options) options = {};
		if (!options.postMessageSyntax) options.postMessageSyntax = 'postMessage';
		if (!options.paddingBottom) options.paddingBottom = '0';

		const cacheKey = this.makeContentKey(this.loadedResources_, body, style, options);
		if (this.cachedContentKey_ === cacheKey) return this.cachedContent_;

		const md = new MarkdownIt({
			breaks: true,
			linkify: true,
			html: true,
		});

		// This is currently used only so that the $expression$ and $$\nexpression\n$$ blocks are translated
		// to math_inline and math_block blocks. These blocks are then processed directly with the Katex
		// library.  It is better this way as then it is possible to conditionally load the CSS required by
		// Katex and use an up-to-date version of Katex (as of 2018, the plugin is still using 0.6, which is
		// buggy instead of 0.9).
		md.use(require('markdown-it-katex'));

		// Hack to make checkboxes clickable. Ideally, checkboxes should be parsed properly in
		// renderTokens_(), but for now this hack works. Marking it with HORRIBLE_HACK so
		// that it can be removed and replaced later on.
		const HORRIBLE_HACK = true;

		if (HORRIBLE_HACK) {
			let counter = -1;
			while (body.indexOf('- [ ]') >= 0 || body.indexOf('- [X]') >= 0 || body.indexOf('- [x]') >= 0) {
				body = body.replace(/- \[(X| |x)\]/, function(v, p1) {
					let s = p1 == ' ' ? 'NOTICK' : 'TICK';
					counter++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -389,7 +389,7 @@
 		const md = new MarkdownIt({
 			breaks: true,
 			linkify: true,
-			html: true,
+			html: false, // For security, HTML tags are not supported - https://github.com/laurent22/joplin/issues/500
 		});
 
 		// This is currently used only so that the $expression$ and $$\nexpression\n$$ blocks are translated
@@ -434,6 +434,9 @@
 				if (loopCount++ >= 9999) break;
 			}
 		}
+
+		// Support <br> tag to allow newlines inside table cells
+		renderedBody = renderedBody.replace(/&lt;br&gt;/gi, '<br>');
 
 		// https://necolas.github.io/normalize.css/
 		const normalizeCss = `
```
