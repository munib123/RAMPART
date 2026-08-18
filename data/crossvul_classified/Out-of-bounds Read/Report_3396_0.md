# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3396_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3396_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2303-2344 of the vulnerable file.

            stop = TRUE;
          }

          break;

        case RE_OPCODE_ANY:

          bytes_matched++;
          input += input_incr;
          ip += 1;

          break;

        case RE_OPCODE_REPEAT_ANY_UNGREEDY:

          repeat_any_args = (RE_REPEAT_ANY_ARGS*)(ip + 1);
          next_opcode = ip + 1 + sizeof(RE_REPEAT_ANY_ARGS);

          for (i = repeat_any_args->min + 1; i <= repeat_any_args->max; i++)
          {
            next_input = input + i * input_incr;

            if (bytes_matched + i >= max_bytes_matched)
              break;

            if ( *(next_opcode) != RE_OPCODE_LITERAL ||
                (*(next_opcode) == RE_OPCODE_LITERAL &&
                 *(next_opcode + 1) == *next_input))
            {
              if (sp >= MAX_FAST_RE_STACK)
                return -4;

              code_stack[sp] = next_opcode;
              input_stack[sp] = next_input;
              matches_stack[sp] = bytes_matched + i;
              sp++;
            }
          }

          input += input_incr * repeat_any_args->min;
          bytes_matched += repeat_any_args->min;
          ip = next_opcode;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2320,10 +2320,10 @@
 
           for (i = repeat_any_args->min + 1; i <= repeat_any_args->max; i++)
           {
-            next_input = input + i * input_incr;
-
             if (bytes_matched + i >= max_bytes_matched)
               break;
+
+            next_input = input + i * input_incr;
 
             if ( *(next_opcode) != RE_OPCODE_LITERAL ||
                 (*(next_opcode) == RE_OPCODE_LITERAL &&
@@ -2341,6 +2341,7 @@
 
           input += input_incr * repeat_any_args->min;
           bytes_matched += repeat_any_args->min;
+          bytes_matched = yr_min(bytes_matched, max_bytes_matched);
           ip = next_opcode;
 
           break;
```
