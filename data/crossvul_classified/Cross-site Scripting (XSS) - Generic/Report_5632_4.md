# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in json
**Pair ID:** 5632_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5632_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "name": "jplayer",
  "version": "2.3.1",
  "description": "The jQuery HTML5 Audio / Video Library",
  "homepage": "http://www.jplayer.org/",
  "keywords": [
    "audio",
    "video"
  ],
  "dependencies": {
    "jquery": ">1.4.2"
  },
  "licenses": [
    {
      "type": "MIT",
      "url": "http://www.opensource.org/licenses/mit-license.php"
    },
    {
      "type" : "GPL",
      "url": "http://www.gnu.org/copyleft/gpl.html"
    }
  ],
  "repositories": [
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "name": "jplayer",
-  "version": "2.3.1",
+  "version": "2.3.2",
   "description": "The jQuery HTML5 Audio / Video Library",
   "homepage": "http://www.jplayer.org/",
   "keywords": [
```
