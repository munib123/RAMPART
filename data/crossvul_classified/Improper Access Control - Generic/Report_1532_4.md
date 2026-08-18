# CrossVul Fix Pair: Improper Access Control in json
**Pair ID:** 1532_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1532_4`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```json
Lines 1-23 of the vulnerable file.

{
  "description2":{
    "message":"The most popular Chrome extension in the world, a customizable ad blocker that blocks ALL ads for free by default.",
    "description":"Extension description in manifest. Should not exceed 132 characters."
  },
  "adblock_click_for_details":{
    "message":"AdBlock - click for details",
    "description":"Tooltip on the AdBlock button, to help users understand that they can click the button, and that they can control the number badge that appears on the button."
  },
  "buttoncancel":{
    "message":"Cancel",
    "description":"Cancel button"
  },
  "buttonok":{
    "message":"OK!",
    "description":"OK button"
  },
  "reportpubliclyavailable":{
    "message":"Note: your report may become publicly available. Keep that in mind before including anything private.",
    "description":"Ad report page string, when you're about to submit a report"
  },
  "buttonblockit":{
    "message":"Block it!",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 {
   "description2":{
-    "message":"The most popular Chrome extension in the world, a customizable ad blocker that blocks ALL ads for free by default.",
+    "message":"AdBlock. The #1 ad blocker with over 200 million downloads. Blocks YouTube, Facebook and ALL ads by default (unlike Adblock Plus).",
     "description":"Extension description in manifest. Should not exceed 132 characters."
   },
   "adblock_click_for_details":{
@@ -191,6 +191,16 @@
     "message":"This AdBlock feature does not work on this site because it uses out of date technology. You can blacklist or whitelist resources manually in the 'Customize' tab of the options page.",
     "description":"Message (alert) shown when the user tries to use a blacklist\/whitelist wizard on an old website"
   },
+  "subscribeconfirm":{
+    "message":"Are you sure that you want to subscribe to the $title$ filter list?",
+    "description":"Prompt question before subscribing to the filter list",
+    "placeholders":{
+      "title":{
+        "content":"$1",
+        "example":"Prebake"
+      }
+    }
+  },
   "subscribingtitle":{
     "message":"Subscribing to filter list...",
     "description":"abp: link subscriber title"
```
