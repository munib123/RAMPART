# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1921_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1921_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 4-28 of the vulnerable file.

import DiscussionPage from 'flarum/components/DiscussionPage';
import IndexPage from 'flarum/components/IndexPage';
import { truncate } from 'flarum/utils/string';

export default function addStickyControl() {
  extend(DiscussionListState.prototype, 'requestParams', function(params) {
    if (app.current.matches(IndexPage) || app.current.matches(DiscussionPage)) {
      params.include.push('firstPost');
    }
  });

  extend(DiscussionListItem.prototype, 'infoItems', function(items) {
    const discussion = this.attrs.discussion;

    if (discussion.isSticky() && !this.attrs.params.q && !discussion.lastReadPostNumber()) {
      const firstPost = discussion.firstPost();

      if (firstPost) {
        const excerpt = truncate(firstPost.contentPlain(), 175);

        items.add('excerpt', m.trust(excerpt), -100);
      }
    }
  });
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,8 @@
       if (firstPost) {
         const excerpt = truncate(firstPost.contentPlain(), 175);
 
-        items.add('excerpt', m.trust(excerpt), -100);
+        // Wrapping in <div> because ItemList entries need to be vnodes
+        items.add('excerpt', <div>{excerpt}</div>, -100);
       }
     }
   });
```
