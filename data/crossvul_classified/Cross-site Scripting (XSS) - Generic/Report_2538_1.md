# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in typescript
**Pair ID:** 2538_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2538_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```typescript
Lines 24-64 of the vulnerable file.

        if (lang === 'mermaid') {
            if (mermaid === undefined) {
                mermaid = require('mermaid');
                mermaid.init(undefined, 'div.mermaid');
            }
            return '<div class="mermaid">' + he.encode(code) + '</div>';
        }

        if (lang === 'katex') {
            return '<div class="katex">' + katex.renderToString(code, {displayMode: true}) + '</div>';
        }

        try {
            return highlight(lang, code).value;
        } catch (e) {
            console.log('Error on highlight: ' + e.message);
            return code;
        }
    },

    emoji(name: string) {
        return emoji_replacer.replaceOne(name);
    },
});

const REGEX_CHECKED_LISTITEM = /^\[x]\s+/;
const REGEX_UNCHECKED_LISTITEM = /^\[ ]\s+/;

class MarkdownRenderer {
    public outline: Heading[];
    private renderer: MarkedRenderer;
    private link_id: number;
    private tooltips: string;

    constructor(public markdown_exts: string[]) {
        this.renderer = new marked.Renderer();

        // TODO:
        // 'this' is set to renderer methods automatically so we need to preserve
        // this scope's 'this' as 'self'.
        /* tslint:disable:no-this-assignment */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,9 +41,12 @@
         }
     },
 
+    // @ts-ignore: emoji is a dedicated method added by my fork
     emoji(name: string) {
         return emoji_replacer.replaceOne(name);
     },
+
+    sanitize: 1,
 });
 
 const REGEX_CHECKED_LISTITEM = /^\[x]\s+/;
@@ -51,7 +54,7 @@
 
 class MarkdownRenderer {
     public outline: Heading[];
-    private renderer: MarkedRenderer;
+    private renderer: marked.Renderer;
     private link_id: number;
     private tooltips: string;
 
```
