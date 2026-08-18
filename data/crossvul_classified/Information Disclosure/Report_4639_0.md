# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 4639_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4639_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 21-61 of the vulnerable file.

    }

    return url
  }

  const conversionResult = await runWithTimeout(async (executionInfo, reject) => {
    const chromeVersion = await browser.version()

    if (executionInfo.error) {
      return
    }

    reporter.logger.debug(`Converting with chrome ${chromeVersion} using ${strategy} strategy`, req)

    const page = await browser.newPage()

    if (executionInfo.error) {
      return
    }

    page.on('pageerror', (err) => {
      pageLog('warn', `Page error: ${err.message}${err.stack ? ` , stack: ${err.stack}` : ''}`)
    })

    page.on('error', (err) => {
      err.workerCrashed = true

      if (!page.isClosed()) {
        page.close().catch(() => {})
      }

      reject(err)
    })

    page.on('console', (m) => {
      pageLog('debug', m.text())
    })

    page.on('request', (r) => {
      let detail = ''

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,12 @@
       return
     }
 
+    await page.setRequestInterception(true)
+
+    if (executionInfo.error) {
+      return
+    }
+
     page.on('pageerror', (err) => {
       pageLog('warn', `Page error: ${err.message}${err.stack ? ` , stack: ${err.stack}` : ''}`)
     })
@@ -64,6 +70,19 @@
       }
 
       pageLog('debug', `Page request: ${r.method()} (${r.resourceType()}) ${trimUrl(r.url())}${detail}`)
+
+      const isRelativeToHtmlUrl = r.url().lastIndexOf(htmlUrl, 0) === 0
+
+      if (
+        !isRelativeToHtmlUrl &&
+        // potentially dangerous request to local file
+        r.url().lastIndexOf('file:///', 0) === 0
+      ) {
+        r.abort('accessdenied')
+        return
+      }
+
+      r.continue()
     })
 
     page.on('requestfinished', (r) => {
```
