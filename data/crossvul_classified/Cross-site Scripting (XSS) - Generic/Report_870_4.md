# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 870_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `870_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "shave",
  "version": "2.5.2",
  "description": "Shave is a javascript plugin that truncates multi-line text within a html element based on set max height",
  "main": "dist/shave.js",
  "module": "dist/shave.es.js",
  "unpkg": "dist/shave.min.js",
  "files": [
    "dist",
    "src",
    "types"
  ],
  "types": "types/index.d.ts",
  "scripts": {
    "build": "rollup --config rollup.config.js",
    "chore:delete-changelog-branch": "if git show-ref --quiet refs/heads/chore-changelog; then git branch -D chore-changelog; fi",
    "chore:branch": "git checkout -b chore-changelog",
    "chore:changelog": "conventional-changelog -p eslint -i CHANGELOG.md -s -r 0",
    "chore:setup-next-work": "git checkout master && npm run chore:delete-changelog-branch",
    "chore:pr": "git add . && git commit -m '[chore] updates changelog' --no-verify && git push origin chore-changelog -f",
    "chore:setup-changelog": "git checkout master && git pull",
    "chore": "npm run chore:delete-changelog-branch && npm run chore:branch && npm run chore:changelog && npm run chore:pr && npm run chore:setup-next-work",
    "eslint": "eslint . --fix",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "shave",
-  "version": "2.5.2",
+  "version": "2.5.3",
   "description": "Shave is a javascript plugin that truncates multi-line text within a html element based on set max height",
   "main": "dist/shave.js",
   "module": "dist/shave.es.js",
```
