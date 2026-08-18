# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4618_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4618_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 44-71 of the vulnerable file.

};

module.exports.checkout = function (callback) {
  cp.exec(gitApp + " checkout -- .", gitExtra, callback);
};

module.exports.commit = function (files, message, newVer, tagName, callback) {
  message = escapeQuotes(message.replace("%s", newVer));
  files = files.map(escapeQuotes).join(" ");
  var functionSeries = [
    function (done) {
      cp.exec(gitApp + " add " + files, gitExtra, done);
    },

    function (done) {
      cp.exec([gitApp, "commit", "-m", message].join(" "), gitExtra, done);
    },

    function (done) {
      cp.exec(
        [gitApp, "tag", "-a", tagName, "-m", message].join(" "),
        gitExtra,
        done
      );
    },
  ];
  contra.series(functionSeries, callback);
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,7 @@
 
     function (done) {
       cp.exec(
-        [gitApp, "tag", "-a", tagName, "-m", message].join(" "),
+        [gitApp, "tag", "-a", escapeQuotes(tagName), "-m", message].join(" "),
         gitExtra,
         done
       );
```
