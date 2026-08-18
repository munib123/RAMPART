# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 252_5
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `252_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.


void test_base64_encode(void)
{
  char buffer[16];
  size_t len = mutt_b64_encode(buffer, clear, sizeof(clear) - 1, sizeof(buffer));
  if (!TEST_CHECK(len == sizeof(encoded) - 1))
  {
    TEST_MSG("Expected: %zu", sizeof(encoded) - 1);
    TEST_MSG("Actual  : %zu", len);
  }
  if (!TEST_CHECK(strcmp(buffer, encoded) == 0))
  {
    TEST_MSG("Expected: %zu", encoded);
    TEST_MSG("Actual  : %zu", buffer);
  }
}

void test_base64_decode(void)
{
  char buffer[16];
  int len = mutt_b64_decode(buffer, encoded);
  if (!TEST_CHECK(len == sizeof(clear) - 1))
  {
    TEST_MSG("Expected: %zu", sizeof(clear) - 1);
    TEST_MSG("Actual  : %zu", len);
  }
  buffer[len] = '\0';
  if (!TEST_CHECK(strcmp(buffer, clear) == 0))
  {
    TEST_MSG("Expected: %s", clear);
    TEST_MSG("Actual  : %s", buffer);
  }
}

void test_base64_lengths(void)
{
  const char *in = "FuseMuse";
  char out1[32];
  char out2[32];
  size_t enclen;
  int declen;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 void test_base64_decode(void)
 {
   char buffer[16];
-  int len = mutt_b64_decode(buffer, encoded);
+  int len = mutt_b64_decode(buffer, encoded, sizeof(buffer));
   if (!TEST_CHECK(len == sizeof(clear) - 1))
   {
     TEST_MSG("Expected: %zu", sizeof(clear) - 1);
@@ -59,7 +59,7 @@
 
   /* Decoding a zero-length string should fail, too */
   out1[0] = '\0';
-  declen = mutt_b64_decode(out2, out1);
+  declen = mutt_b64_decode(out2, out1, sizeof(out2));
   if (!TEST_CHECK(declen == -1))
   {
     TEST_MSG("Expected: %zu", -1);
@@ -76,7 +76,7 @@
       TEST_MSG("Expected: %zu", exp);
       TEST_MSG("Actual  : %zu", enclen);
     }
-    declen = mutt_b64_decode(out2, out1);
+    declen = mutt_b64_decode(out2, out1, sizeof(out2));
     if (!TEST_CHECK(declen == i))
     {
       TEST_MSG("Expected: %zu", i);
```
