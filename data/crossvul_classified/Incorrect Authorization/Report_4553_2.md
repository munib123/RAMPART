# CrossVul Fix Pair: Incorrect Authorization in javascript
**Pair ID:** 4553_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4553_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```javascript
Lines 86-126 of the vulnerable file.

      }
      if (req.body._InstallationId) {
        info.installationId = req.body._InstallationId;
        delete req.body._InstallationId;
      }
      if (req.body._SessionToken) {
        info.sessionToken = req.body._SessionToken;
        delete req.body._SessionToken;
      }
      if (req.body._MasterKey) {
        info.masterKey = req.body._MasterKey;
        delete req.body._MasterKey;
      }
      if (req.body._ContentType) {
        req.headers['content-type'] = req.body._ContentType;
        delete req.body._ContentType;
      }
    } else {
      return invalidRequest(req, res);
    }
  }

  if (info.clientVersion) {
    info.clientSDK = ClientSDK.fromString(info.clientVersion);
  }

  if (fileViaJSON) {
    // We need to repopulate req.body with a buffer
    var base64 = req.body.base64;
    req.body = Buffer.from(base64, 'base64');
  }

  const clientIp = getClientIp(req);

  info.app = AppCache.get(info.appId);
  req.config = Config.get(info.appId, mount);
  req.config.headers = req.headers || {};
  req.config.ip = clientIp;
  req.info = info;

  if (
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,10 @@
     } else {
       return invalidRequest(req, res);
     }
+  }
+
+  if (info.sessionToken && typeof info.sessionToken !== 'string') {
+    info.sessionToken = info.sessionToken.toString();
   }
 
   if (info.clientVersion) {
```
