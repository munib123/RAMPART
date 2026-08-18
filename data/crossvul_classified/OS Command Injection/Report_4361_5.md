# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 4361_5
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4361_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1023-1064 of the vulnerable file.

      if ({}.hasOwnProperty.call(sections, i)) {
        if (sections[i].trim() !== '') {
          let lines = sections[i].trim().split('\r\n');
          perfData.push({
            name: util.getValue(lines, 'Name', '=').replace(/[()\[\] ]+/g, '').replace('#', '_').toLowerCase(),
            rx_bytes: parseInt(util.getValue(lines, 'BytesReceivedPersec', '='), 10),
            rx_errors: parseInt(util.getValue(lines, 'PacketsReceivedErrors', '='), 10),
            rx_dropped: parseInt(util.getValue(lines, 'PacketsReceivedDiscarded', '='), 10),
            tx_bytes: parseInt(util.getValue(lines, 'BytesSentPersec', '='), 10),
            tx_errors: parseInt(util.getValue(lines, 'PacketsOutboundErrors', '='), 10),
            tx_dropped: parseInt(util.getValue(lines, 'PacketsOutboundDiscarded', '='), 10)
          });
        }
      }
    }
    return perfData;
  }

  return new Promise((resolve) => {
    process.nextTick(() => {

      const ifaceSanitized = util.isPrototypePolluted() ? '---' : util.sanitizeShellString(iface);

      let result = {
        iface: ifaceSanitized,
        operstate: 'unknown',
        rx_bytes: 0,
        rx_dropped: 0,
        rx_errors: 0,
        tx_bytes: 0,
        tx_dropped: 0,
        tx_errors: 0,
        rx_sec: -1,
        tx_sec: -1,
        ms: 0
      };

      let operstate = 'unknown';
      let rx_bytes = 0;
      let tx_bytes = 0;
      let rx_dropped = 0;
      let rx_errors = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1040,8 +1040,13 @@
 
   return new Promise((resolve) => {
     process.nextTick(() => {
-
-      const ifaceSanitized = util.isPrototypePolluted() ? '---' : util.sanitizeShellString(iface);
+      let ifaceSanitized = '';
+      const s = util.isPrototypePolluted() ? '---' : util.sanitizeShellString(iface);
+      for (let i = 0; i <= 2000; i++) {
+        if (!(s[i] === undefined)) {
+          ifaceSanitized = ifaceSanitized + s[i];
+        }
+      }
 
       let result = {
         iface: ifaceSanitized,
```
