# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 1197_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1197_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 600-640 of the vulnerable file.

  input_u32[inlen] = 0;

  input_u8 = u32_to_u8 (input_u32, inlen + 1, NULL, &length);
  free (input_u32);
  if (!input_u8)
    {
      if (errno == ENOMEM)
	return IDN2_MALLOC;
      return IDN2_ENCODING_ERROR;
    }

  rc = idn2_lookup_u8 (input_u8, &output_u8, flags);
  free (input_u8);

  if (rc == IDN2_OK)
    {
      /* wow, this is ugly, but libidn manpage states:
       * char * out  output zero terminated string that must have room for at
       * least 63 characters plus the terminating zero.
       */
      if (output)
	strcpy (output, (const char *) output_u8);

      free(output_u8);
    }

  return rc;
}

/**
 * idn2_to_ascii_4z:
 * @input: zero terminated input Unicode (UCS-4) string.
 * @output: pointer to newly allocated zero-terminated output string.
 * @flags: optional #idn2_flags to modify behaviour.
 *
 * Convert UCS-4 domain name to ASCII string using the IDNA2008
 * rules.  The domain name may contain several labels, separated by dots.
 * The output buffer must be deallocated by the caller.
 *
 * The default behavior of this function (when flags are zero) is to apply
 * the IDNA2008 rules without the TR46 amendments. As the TR46
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -617,10 +617,18 @@
        * char * out  output zero terminated string that must have room for at
        * least 63 characters plus the terminating zero.
        */
+      size_t len = strlen ((char *) output_u8);
+
+      if (len > 63)
+        {
+	  free (output_u8);
+	  return IDN2_TOO_BIG_DOMAIN;
+        }
+
       if (output)
-	strcpy (output, (const char *) output_u8);
-
-      free(output_u8);
+	strcpy (output, (char *) output_u8);
+
+      free (output_u8);
     }
 
   return rc;
```
