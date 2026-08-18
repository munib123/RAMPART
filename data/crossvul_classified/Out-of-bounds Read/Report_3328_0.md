# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3328_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3328_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 833-873 of the vulnerable file.


      case OP_MATCHES:

        pop(r2);
        pop(r1);

        ensure_defined(r2);
        ensure_defined(r1);

        if (r1.ss->length == 0)
        {
          r1.i = FALSE;
          push(r1);
          break;
        }

        r1.i = yr_re_exec(
          (uint8_t*) r2.re->code,
          (uint8_t*) r1.ss->c_string,
          r1.ss->length,
          r2.re->flags | RE_FLAGS_SCAN,
          NULL,
          NULL) >= 0;

        push(r1);
        break;

      case OP_INT_TO_DBL:
        r1.i = *(uint64_t*)(ip + 1);
        ip += sizeof(uint64_t);
        r2 = stack[sp - r1.i];
        if (is_undef(r2))
          stack[sp - r1.i].i = UNDEFINED;
        else
          stack[sp - r1.i].d = (double) r2.i;
        break;

      case OP_STR_TO_BOOL:
        pop(r1);
        ensure_defined(r1);
        r1.i = r1.ss->length > 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -850,6 +850,7 @@
           (uint8_t*) r2.re->code,
           (uint8_t*) r1.ss->c_string,
           r1.ss->length,
+          0,
           r2.re->flags | RE_FLAGS_SCAN,
           NULL,
           NULL) >= 0;
```
