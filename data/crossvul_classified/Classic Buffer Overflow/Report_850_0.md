# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in cpp
**Pair ID:** 850_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `850_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```cpp
Lines 3592-3633 of the vulnerable file.

      onig_error_code_to_str(err_str, err);
      raise_warning("mbregex search failure: %s", err_str);
      break;
    }
    if (err >= 0) {
#if moriyoshi_0
      if (regs->beg[0] == regs->end[0]) {
        raise_warning("Empty regular expression");
        break;
      }
#endif
      /* copy the part of the string before the match */
      out_buf.append((const char *)pos,
                     (OnigUChar *)(str.data() + regs->beg[0]) - pos);
      /* copy replacement and backrefs */
      i = 0;
      p = replacement.data();
      while (i < replacement.size()) {
        int fwd = (int)php_mb_mbchar_bytes_ex(p, enc);
        n = -1;
        if ((replacement.size() - i) >= 2 && fwd == 1 &&
          p[0] == '\\' && p[1] >= '0' && p[1] <= '9') {
          n = p[1] - '0';
        }
        if (n >= 0 && n < regs->num_regs) {
          if (regs->beg[n] >= 0 && regs->beg[n] < regs->end[n] &&
              regs->end[n] <= str.size()) {
            out_buf.append(str.data() + regs->beg[n],
                           regs->end[n] - regs->beg[n]);
          }
          p += 2;
          i += 2;
        } else {
          out_buf.append(p, fwd);
          p += fwd;
          i += fwd;
        }
      }
      n = regs->end[0];
      if ((pos - (OnigUChar *)str.data()) < n) {
        pos = (OnigUChar *)(str.data() + n);
      } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3609,8 +3609,9 @@
       while (i < replacement.size()) {
         int fwd = (int)php_mb_mbchar_bytes_ex(p, enc);
         n = -1;
-        if ((replacement.size() - i) >= 2 && fwd == 1 &&
-          p[0] == '\\' && p[1] >= '0' && p[1] <= '9') {
+        auto const remaining = replacement.size() - i;
+        if (remaining >= 2 && fwd == 1 &&
+            p[0] == '\\' && p[1] >= '0' && p[1] <= '9') {
           n = p[1] - '0';
         }
         if (n >= 0 && n < regs->num_regs) {
@@ -3621,10 +3622,14 @@
           }
           p += 2;
           i += 2;
-        } else {
+        } else if (remaining >= fwd) {
           out_buf.append(p, fwd);
           p += fwd;
           i += fwd;
+        } else {
+          raise_warning("Replacement ends with unterminated %s: 0x%hhx",
+                        enc->name, *p);
+          break;
         }
       }
       n = regs->end[0];
```
