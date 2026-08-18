# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4357_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4357_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1-37 of the vulnerable file.

export default async function ({ addon, console }) {
  await addon.tab.loadScript("https://cdn.jsdelivr.net/npm/linkifyjs@2.1.9/dist/linkify.min.js");
  await addon.tab.loadScript("https://cdn.jsdelivr.net/npm/linkifyjs@2.1.9/dist/linkify-element.min.js");

  const pageType = document.location.pathname.substr(1).split("/")[0];

  switch (pageType) {
    case "users":
      document.querySelectorAll("#user-details .read-only").forEach((element) => linkifyElement(element));
      break;

    case "projects":
      (async () => {
        while (true) {
          let element = await addon.tab.waitForElement(".project-description", { markAsSeen: true });
          // Need to convert #[numbers] to solve conflict between tags and external Scratch player links.
          document.querySelectorAll(".project-description a").forEach((element) => {
            if (/\d+/.test(element.textContent)) element.outerHTML = element.textContent;
          });
          element.normalize();
          linkifyElement(element);
        }
      })();
      break;

    case "studios":
      linkifyElement(document.querySelector("#description.read-only .overview"));
      break;
  }

  (async () => {
    while (true) {
      let comment = await addon.tab.waitForElement(".comment", { markAsSeen: true });
      linkifyElement(comment);
    }
  })();
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,7 +15,10 @@
           let element = await addon.tab.waitForElement(".project-description", { markAsSeen: true });
           // Need to convert #[numbers] to solve conflict between tags and external Scratch player links.
           document.querySelectorAll(".project-description a").forEach((element) => {
-            if (/\d+/.test(element.textContent)) element.outerHTML = element.textContent;
+              if (/^#\d+$/.test(element.textContent) && element.previousSibling instanceof Text) {
+                  element.previousSibling.textContent += element.textContent;
+                  element.remove();
+              }
           });
           element.normalize();
           linkifyElement(element);
```
