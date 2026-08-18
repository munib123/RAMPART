# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5493_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5493_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1357-1397 of the vulnerable file.

                        co_test[i].num);

    if(memcmp(co_test[i].result,
              co_test[i].expected,
              strlen(co_test[i].expected))) {
      printf("curl_off_t test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, co_test[i].expected, co_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() curl_off_t tests OK!\n");
  else
    printf("Some curl_mprintf() curl_off_t tests Failed!\n");

  return failed;
}

static int string_check(char *buf, const char *buf2)
{
  if(strcmp(buf, buf2)) {
    /* they shouldn't differ */
    printf("sprintf failed:\nwe '%s'\nsystem: '%s'\n",
           buf, buf2);
    return 1;
  }
  return 0;
}

/*
 * The output strings in this test need to have been verified with a system
 * sprintf() before used here.
 */
static int test_string_formatting(void)
{
  int errors = 0;
  char buf[256];
  curl_msnprintf(buf, sizeof(buf), "%0*d%s", 2, 9, "foo");
  errors += string_check(buf, "09foo");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1374,16 +1374,31 @@
   return failed;
 }
 
-static int string_check(char *buf, const char *buf2)
+static int _string_check(int linenumber, char *buf, const char *buf2)
 {
   if(strcmp(buf, buf2)) {
     /* they shouldn't differ */
-    printf("sprintf failed:\nwe '%s'\nsystem: '%s'\n",
-           buf, buf2);
+    printf("sprintf line %d failed:\nwe      '%s'\nsystem: '%s'\n",
+           linenumber, buf, buf2);
     return 1;
   }
   return 0;
 }
+#define string_check(x,y) _string_check(__LINE__, x, y)
+
+static int _strlen_check(int linenumber, char *buf, size_t len)
+{
+  size_t buflen = strlen(buf);
+  if(len != buflen) {
+    /* they shouldn't differ */
+    printf("sprintf strlen:%d failed:\nwe '%d'\nsystem: '%d'\n",
+           linenumber, buflen, len);
+    return 1;
+  }
+  return 0;
+}
+
+#define strlen_check(x,y) _strlen_check(__LINE__, x, y)
 
 /*
  * The output strings in this test need to have been verified with a system
@@ -1523,6 +1538,119 @@
   return errors;
 }
 
+/* DBL_MAX value from Linux */
+#define MAXIMIZE -179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368.000000
+
+static int test_float_formatting(void)
+{
+  int errors = 0;
+  char buf[512]; /* larger than max float size */
+  curl_msnprintf(buf, sizeof(buf), "%f", 9.0);
+  errors += string_check(buf, "9.000000");
+
+  curl_msnprintf(buf, sizeof(buf), "%.1f", 9.1);
+  errors += string_check(buf, "9.1");
+
+  curl_msnprintf(buf, sizeof(buf), "%.2f", 9.1);
+  errors += string_check(buf, "9.10");
+
+  curl_msnprintf(buf, sizeof(buf), "%.0f", 9.1);
+  errors += string_check(buf, "9");
+
+  curl_msnprintf(buf, sizeof(buf), "%0f", 9.1);
+  errors += string_check(buf, "9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%10f", 9.1);
+  errors += string_check(buf, "  9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%10.3f", 9.1);
+  errors += string_check(buf, "     9.100");
+
+  curl_msnprintf(buf, sizeof(buf), "%-10.3f", 9.1);
+  errors += string_check(buf, "9.100     ");
+
+  curl_msnprintf(buf, sizeof(buf), "%-10.3f", 9.123456);
+  errors += string_check(buf, "9.123     ");
+
+  curl_msnprintf(buf, sizeof(buf), "%.-2f", 9.1);
+  errors += string_check(buf, "9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 10, 9.1);
+  errors += string_check(buf, "  9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 3, 9.1);
+  errors += string_check(buf, "9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.2987654);
+  errors += string_check(buf, "9.298765");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.298765);
+  errors += string_check(buf, "9.298765");
+
+  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.29876);
+  errors += string_check(buf, "9.298760");
+
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 6, 9.2987654);
+  errors += string_check(buf, "9.298765");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 5, 9.2987654);
+  errors += string_check(buf, "9.29877");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 4, 9.2987654);
+  errors += string_check(buf, "9.2988");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 3, 9.2987654);
+  errors += string_check(buf, "9.299");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 2, 9.2987654);
+  errors += string_check(buf, "9.30");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 1, 9.2987654);
+  errors += string_check(buf, "9.3");
+  curl_msnprintf(buf, sizeof(buf), "%.*f", 0, 9.2987654);
+  errors += string_check(buf, "9");
+
+  /* very large precisions easily turn into system specific outputs so we only
+     check the output buffer length here as we know the internal limit */
+
+  curl_msnprintf(buf, sizeof(buf), "%.*f", (1<<30), 9.2987654);
+  errors += strlen_check(buf, 325);
+
+  curl_msnprintf(buf, sizeof(buf), "%10000.10000f", 9.2987654);
+  errors += strlen_check(buf, 325);
+
+  curl_msnprintf(buf, sizeof(buf), "%240.10000f",
+                 123456789123456789123456789.2987654);
+  errors += strlen_check(buf, 325);
+
+  /* 1<<31 turns negative (-2147483648) when used signed */
+  curl_msnprintf(buf, sizeof(buf), "%*f", (1<<31), 9.1);
+  errors += string_check(buf, "9.100000");
+
+  /* curl_msnprintf() limits a single float output to 325 bytes maximum
+     width */
+  curl_msnprintf(buf, sizeof(buf), "%*f", (1<<30), 9.1);
+  errors += string_check(buf, "                                                                                                                                                                                                                                                                                                                             9.100000");
+  curl_msnprintf(buf, sizeof(buf), "%100000f", 9.1);
+  errors += string_check(buf, "                                                                                                                                                                                                                                                                                                                             9.100000");
+
+  curl_msnprintf(buf, sizeof(buf), "%f", MAXIMIZE);
+  errors += strlen_check(buf, 317);
+
+  curl_msnprintf(buf, 2, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 1);
+  curl_msnprintf(buf, 3, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 2);
+  curl_msnprintf(buf, 4, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 3);
+  curl_msnprintf(buf, 5, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 4);
+  curl_msnprintf(buf, 6, "%f", MAXIMIZE);
+  errors += strlen_check(buf, 5);
+
+  if(!errors)
+    printf("All float strings tests OK!\n");
+  else
+    printf("test_float_formatting Failed!\n");
+
+  return errors;
+}
+
 
 int test(char *URL)
 {
@@ -1546,6 +1674,8 @@
   errors += test_curl_off_t_formatting();
 
   errors += test_string_formatting();
+
+  errors += test_float_formatting();
 
   if(errors)
     return TEST_ERR_MAJOR_BAD;
```
