# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3375_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3375_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 3003-3043 of the vulnerable file.


      prev = p;
      if (IS_SYNTAX_OP2(syn, ONIG_SYN_OP2_ESC_U_HEX4)) {
        num = scan_unsigned_hexadecimal_number(&p, end, 4, enc);
        if (num < 0) return ONIGERR_TOO_BIG_NUMBER;
        if (p == prev) {  /* can't read nothing. */
          num = 0; /* but, it's not error */
        }
        tok->type   = TK_CODE_POINT;
        tok->base   = 16;
        tok->u.code = (OnigCodePoint )num;
      }
      break;

    case '0':
    case '1': case '2': case '3': case '4': case '5': case '6': case '7':
      if (IS_SYNTAX_OP(syn, ONIG_SYN_OP_ESC_OCTAL3)) {
        PUNFETCH;
        prev = p;
        num = scan_unsigned_octal_number(&p, end, 3, enc);
        if (num < 0) return ONIGERR_TOO_BIG_NUMBER;
        if (p == prev) {  /* can't read nothing. */
          num = 0; /* but, it's not error */
        }
        tok->type = TK_RAW_BYTE;
        tok->base = 8;
        tok->u.c  = num;
      }
      break;

    default:
      PUNFETCH;
      num = fetch_escaped_value(&p, end, env, &c2);
      if (num < 0) return num;
      if (tok->u.c != c2) {
        tok->u.code = c2;
        tok->type   = TK_CODE_POINT;
      }
      break;
    }
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3020,7 +3020,7 @@
         PUNFETCH;
         prev = p;
         num = scan_unsigned_octal_number(&p, end, 3, enc);
-        if (num < 0) return ONIGERR_TOO_BIG_NUMBER;
+        if (num < 0 || num >= 256) return ONIGERR_TOO_BIG_NUMBER;
         if (p == prev) {  /* can't read nothing. */
           num = 0; /* but, it's not error */
         }
@@ -3392,7 +3392,7 @@
       if (IS_SYNTAX_OP(syn, ONIG_SYN_OP_ESC_OCTAL3)) {
         prev = p;
         num = scan_unsigned_octal_number(&p, end, (c == '0' ? 2:3), enc);
-        if (num < 0) return ONIGERR_TOO_BIG_NUMBER;
+        if (num < 0 || num >= 256) return ONIGERR_TOO_BIG_NUMBER;
         if (p == prev) {  /* can't read nothing. */
           num = 0; /* but, it's not error */
         }
```
