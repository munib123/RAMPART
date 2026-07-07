# HackerOne Report: Improper filtering of classes used in codeblocks in Markdown
**Report ID:** 12815
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Redcarpet just uses the name of the language as the classname of the element. So if the classnames are of significance to the site, one can break the site using this. For instance, this report disables the topbar, and can trigger the user into opening a popup. Proof of concept:

```js-topbar
i eat the topbar
```
```js-share-link
i open a popup
```



## Discussion & Remediation Timeline
