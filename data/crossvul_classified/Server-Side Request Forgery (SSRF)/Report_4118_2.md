# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in javascript
**Pair ID:** 4118_2
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4118_2`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```javascript
Lines 8-33 of the vulnerable file.

      return this.reply(502);
    }

    this.connector = new PassiveConnector(this);
    return this.connector.setupServer()
    .then((server) => {
      let address = this.server.options.pasv_url;
      // Allow connecting from local
      if (isLocalIP(this.ip)) {
        address = this.ip;
      }
      const {port} = server.address();
      const host = address.replace(/\./g, ',');
      const portByte1 = port / 256 | 0;
      const portByte2 = port % 256;

      return this.reply(227, `PASV OK (${host},${portByte1},${portByte2})`);
    })
    .catch((err) => {
      log.error(err);
      return this.reply(425);
    });
  },
  syntax: '{{cmd}}',
  description: 'Initiate passive mode'
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
     })
     .catch((err) => {
       log.error(err);
-      return this.reply(425);
+      return this.reply(err.code || 425, err.message);
     });
   },
   syntax: '{{cmd}}',
```
